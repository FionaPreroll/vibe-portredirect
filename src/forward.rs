// PortRedirect - Forwarding data between a TCP connection and a QUIC data stream
//
// Both directions are copied independently, so half-closed connections work: when one side ends
// its sending direction, the other side's sending direction is shut down, too. Aborts are passed
// on as aborts (see docs/PROTOCOL.md): if the TCP connection fails, e.g. because its peer reset
// it, the QUIC stream is reset, and the other side resets its TCP connection in turn.
//
// License: GPL-3.0-only

use anyhow::{anyhow, Result};
use std::fmt::Display;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, info};

use crate::metrics::MetricsCounter;
use crate::protocol::data_stream::StreamErrorCode;

/// How a forwarding ended.
#[derive(Debug)]
pub enum ForwardEnd {
    /// Both directions ended normally.
    Completed,
    /// No data was transferred in either direction for the idle timeout.
    Idle,
    /// Reading from or writing to side A failed.
    AFailed(io::Error),
    /// Reading from or writing to side B failed.
    BFailed(io::Error),
}

/// Forwards data between side A and side B, each given as a reader and a writer, until both
/// directions ended, a side failed or the idle timeout expired.
///
/// When a direction's reader reaches its end, the writer of that direction is shut down, and the
/// other direction goes on. As data is transferred, `counter_a` is incremented by the number of
/// bytes read from A, `counter_b` by those read from B. With `idle_timeout`, forwarding ends when
/// no data was transferred in either direction for that long.
pub async fn forward_bidirectional<AR, AW, BR, BW, StreamName, CounterA, CounterB>(
    (a_read, mut a_write): (AR, AW),
    (b_read, mut b_write): (BR, BW),
    id: StreamName,
    counter_a: CounterA,
    counter_b: CounterB,
    idle_timeout: Option<Duration>,
) -> ForwardEnd
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BR: AsyncRead + Unpin,
    BW: AsyncWrite + Unpin,
    StreamName: Display,
    CounterA: MetricsCounter,
    CounterB: MetricsCounter,
{
    let activity = Activity::new();
    let mut a_read = Tracked::new(a_read, &activity, &counter_a);
    let mut b_read = Tracked::new(b_read, &activity, &counter_b);

    let end = {
        let a_to_b = copy_direction(&mut a_read, &mut b_write);
        let b_to_a = copy_direction(&mut b_read, &mut a_write);
        let idle = async {
            match idle_timeout {
                Some(idle_timeout) => activity.idle_for(idle_timeout).await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(a_to_b, b_to_a, idle);

        let (mut a_to_b_done, mut b_to_a_done) = (false, false);
        loop {
            tokio::select! {
                result = &mut a_to_b, if !a_to_b_done => match result {
                    Ok(()) => a_to_b_done = true,
                    Err(DirectionError::Read(e)) => break ForwardEnd::AFailed(e),
                    Err(DirectionError::Write(e)) => break ForwardEnd::BFailed(e),
                },
                result = &mut b_to_a, if !b_to_a_done => match result {
                    Ok(()) => b_to_a_done = true,
                    Err(DirectionError::Read(e)) => break ForwardEnd::BFailed(e),
                    Err(DirectionError::Write(e)) => break ForwardEnd::AFailed(e),
                },
                () = &mut idle => break ForwardEnd::Idle,
            }
            if a_to_b_done && b_to_a_done {
                break ForwardEnd::Completed;
            }
        }
    };

    match &end {
        ForwardEnd::Idle => info!(
            "Stream (id={}): closed after {:?} without data transfer, forwarded (A:B) ({}:{}) bytes",
            id,
            idle_timeout.unwrap_or_default(),
            a_read.bytes_read,
            b_read.bytes_read
        ),
        _ => info!(
            "Stream (id={}): forwarded (A:B) ({}:{}) bytes",
            id, a_read.bytes_read, b_read.bytes_read
        ),
    }
    end
}

/// Forwards between a TCP connection (side A) and a QUIC data stream (side B), see
/// [`forward_bidirectional`], and passes on aborts:
///
/// - If the TCP connection fails, e.g. because its peer reset it, the QUIC stream is reset and
///   stopped with [`StreamErrorCode::Aborted`].
/// - If the peer aborts the QUIC stream, or the QUIC connection is lost, the TCP connection is
///   reset.
///
/// Returns an error describing the abort, if any. A peer that ends the QUIC stream with code 0,
/// e.g. after its idle timeout, ends the forwarding normally.
pub async fn forward_tcp_and_quic<StreamName, CounterA, CounterB>(
    mut tcp: TcpStream,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    id: StreamName,
    tcp_counter: CounterA,
    quic_counter: CounterB,
    idle_timeout: Option<Duration>,
) -> Result<()>
where
    StreamName: Display,
    CounterA: MetricsCounter,
    CounterB: MetricsCounter,
{
    let end = forward_bidirectional(
        tcp.split(),
        (&mut recv, &mut send),
        &id,
        tcp_counter,
        quic_counter,
        idle_timeout,
    )
    .await;

    let error = match end {
        ForwardEnd::Completed | ForwardEnd::Idle => return Ok(()),
        ForwardEnd::AFailed(e) => anyhow!("the TCP connection failed: {}", e),
        ForwardEnd::BFailed(e) => match QuicStreamEnd::of(&e) {
            QuicStreamEnd::Normal => {
                debug!("Stream (id={}): the peer ended the stream: {}", id, e);
                return Ok(());
            }
            QuicStreamEnd::Aborted(StreamErrorCode::ConnectFailed) => {
                anyhow!("the client could not connect to the destination: {}", e)
            }
            QuicStreamEnd::Aborted(_) => anyhow!("the peer aborted the stream: {}", e),
            QuicStreamEnd::Lost => anyhow!("the QUIC stream failed: {}", e),
        },
    };
    abort_quic_stream(&mut send, &mut recv, StreamErrorCode::Aborted);
    reset_tcp(&tcp);
    Err(error)
}

/// Resets and stops a QUIC data stream with `code`, so the peer stops forwarding it, too.
pub fn abort_quic_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    code: StreamErrorCode,
) {
    // Either direction may already be finished, reset or stopped, which is fine.
    let _ = send.reset(code.code());
    let _ = recv.stop(code.code());
}

/// Makes closing `tcp` reset the connection, so its peer notices the abort instead of seeing a
/// normal end.
pub fn reset_tcp(tcp: &TcpStream) {
    if let Err(e) = tcp.set_zero_linger() {
        debug!("Failed to prepare resetting a TCP connection: {}", e);
    }
}

/// How the peer ended a QUIC stream, judging by the error of a read from it or a write to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicStreamEnd {
    /// The peer stopped or reset the stream with code 0. quinn does that when a stream is
    /// dropped before its end, e.g. after the idle timeout.
    Normal,
    /// The peer aborted the stream with an error code.
    Aborted(StreamErrorCode),
    /// The stream failed otherwise, e.g. because the QUIC connection was lost.
    Lost,
}

impl QuicStreamEnd {
    pub fn of(error: &io::Error) -> Self {
        let code =
            error
                .get_ref()
                .and_then(|inner| match inner.downcast_ref::<quinn::ReadError>() {
                    Some(quinn::ReadError::Reset(code)) => Some(*code),
                    _ => match inner.downcast_ref::<quinn::WriteError>() {
                        Some(quinn::WriteError::Stopped(code)) => Some(*code),
                        _ => None,
                    },
                });
        match code.map(StreamErrorCode::from_code) {
            Some(StreamErrorCode::Ok) => QuicStreamEnd::Normal,
            Some(code) => QuicStreamEnd::Aborted(code),
            None => QuicStreamEnd::Lost,
        }
    }
}

/// Which half of a direction failed.
enum DirectionError {
    Read(io::Error),
    Write(io::Error),
}

/// Copies from `reader` to `writer` until the reader ends, then shuts the writer down.
async fn copy_direction<R, W>(reader: &mut R, writer: &mut W) -> Result<(), DirectionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; crate::PortRedirectProtocol::QUIC_STREAM_READ_BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buf).await.map_err(DirectionError::Read)?;
        if n == 0 {
            return writer.shutdown().await.map_err(DirectionError::Write);
        }
        writer
            .write_all(&buf[..n])
            .await
            .map_err(DirectionError::Write)?;
        writer.flush().await.map_err(DirectionError::Write)?;
    }
}

/// Tracks when data was last transferred, shared by both directions of a forwarding.
struct Activity {
    start: Instant,
    /// Milliseconds since `start` at the last transfer.
    last_transfer_millis: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_transfer_millis: AtomicU64::new(0),
        }
    }

    fn record_transfer(&self) {
        let millis = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_transfer_millis.store(millis, Ordering::Relaxed);
    }

    fn last_transfer(&self) -> Instant {
        self.start + Duration::from_millis(self.last_transfer_millis.load(Ordering::Relaxed))
    }

    /// Completes once no data was transferred for `timeout`.
    async fn idle_for(&self, timeout: Duration) {
        loop {
            let deadline = self.last_transfer() + timeout;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// Wraps a reader to count the bytes read from it and to record the activity.
struct Tracked<'a, R, C> {
    inner: R,
    activity: &'a Activity,
    counter: &'a C,
    bytes_read: u64,
}

impl<'a, R, C> Tracked<'a, R, C> {
    fn new(inner: R, activity: &'a Activity, counter: &'a C) -> Self {
        Self {
            inner,
            activity,
            counter,
            bytes_read: 0,
        }
    }
}

impl<R: AsyncRead + Unpin, C: MetricsCounter> AsyncRead for Tracked<'_, R, C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let bytes = (buf.filled().len() - filled_before) as u64;
        if bytes > 0 {
            this.bytes_read += bytes;
            this.counter.inc_by(bytes);
            this.activity.record_transfer();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::DummyCounter;
    use tokio::io::{duplex, split, DuplexStream};

    /// A reader that returns its data and then ends.
    struct Source(&'static [u8]);

    impl AsyncRead for Source {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = self.0.len().min(buf.remaining());
            buf.put_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Poll::Ready(Ok(()))
        }
    }

    /// A writer that collects what is written to it, or fails writing and shutting down with
    /// the error message `failure`.
    #[derive(Default)]
    struct Sink {
        data: Vec<u8>,
        shut_down: bool,
        failure: Option<&'static str>,
    }

    impl Sink {
        fn failing(failure: &'static str) -> Self {
            Self {
                failure: Some(failure),
                ..Self::default()
            }
        }

        fn result(&self) -> io::Result<()> {
            match self.failure {
                Some(failure) => Err(io::Error::other(failure)),
                None => Ok(()),
            }
        }
    }

    impl AsyncWrite for Sink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.result()?;
            self.data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            self.result()?;
            self.shut_down = true;
            Poll::Ready(Ok(()))
        }
    }

    /// A reader that fails with the error message given.
    struct Failing(&'static str);

    impl AsyncRead for Failing {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other(self.0)))
        }
    }

    #[tokio::test]
    async fn test_forwards_both_directions_and_counts_bytes() {
        let (mut a_sink, mut b_sink) = (Sink::default(), Sink::default());
        let (counter_a, counter_b) = (DummyCounter::new(), DummyCounter::new());

        let end = forward_bidirectional(
            (Source(b"hello"), &mut a_sink),
            (Source(b"world!"), &mut b_sink),
            "test",
            &counter_a,
            &counter_b,
            None,
        )
        .await;

        assert!(matches!(end, ForwardEnd::Completed), "{:?}", end);
        assert_eq!(a_sink.data, b"world!");
        assert_eq!(b_sink.data, b"hello");
        assert!(a_sink.shut_down && b_sink.shut_down);
        assert_eq!(counter_a.get(), 5);
        assert_eq!(counter_b.get(), 6);
    }

    #[tokio::test]
    async fn test_failures_name_the_failing_side() {
        let side_a =
            |end: &ForwardEnd| matches!(end, ForwardEnd::AFailed(e) if e.to_string() == "A");
        let side_b =
            |end: &ForwardEnd| matches!(end, ForwardEnd::BFailed(e) if e.to_string() == "B");

        // Reading from A fails.
        let end = forward(
            (Failing("A"), Sink::default()),
            (tokio::io::empty(), Sink::default()),
        )
        .await;
        assert!(side_a(&end), "{:?}", end);

        // Writing to B fails.
        let end = forward(
            (Source(b"data"), Sink::default()),
            (tokio::io::empty(), Sink::failing("B")),
        )
        .await;
        assert!(side_b(&end), "{:?}", end);

        // Reading from B fails.
        let end = forward(
            (tokio::io::empty(), Sink::default()),
            (Failing("B"), Sink::default()),
        )
        .await;
        assert!(side_b(&end), "{:?}", end);

        // Writing to A fails.
        let end = forward(
            (tokio::io::empty(), Sink::failing("A")),
            (Source(b"data"), Sink::default()),
        )
        .await;
        assert!(side_a(&end), "{:?}", end);

        // Passing on the end of A to B fails.
        let end = forward(
            (tokio::io::empty(), Sink::default()),
            (tokio::io::empty(), Sink::failing("B")),
        )
        .await;
        assert!(side_b(&end), "{:?}", end);
    }

    async fn forward<AR, AW, BR, BW>(a: (AR, AW), b: (BR, BW)) -> ForwardEnd
    where
        AR: AsyncRead + Unpin,
        AW: AsyncWrite + Unpin,
        BR: AsyncRead + Unpin,
        BW: AsyncWrite + Unpin,
    {
        forward_bidirectional(a, b, "test", DummyCounter::new(), DummyCounter::new(), None).await
    }

    type Peer = DuplexStream;

    /// Runs `forward_bidirectional` between the inner ends of two duplex pipes and returns the
    /// outer ends, which play the two peers.
    fn spawn_forwarding(
        idle_timeout: Option<Duration>,
    ) -> (Peer, Peer, tokio::task::JoinHandle<ForwardEnd>) {
        let (peer_a, inner_a) = duplex(1024);
        let (peer_b, inner_b) = duplex(1024);
        let forwarding = tokio::spawn(async move {
            forward_bidirectional(
                split(inner_a),
                split(inner_b),
                "spawned",
                DummyCounter::new(),
                DummyCounter::new(),
                idle_timeout,
            )
            .await
        });
        (peer_a, peer_b, forwarding)
    }

    #[tokio::test]
    async fn test_half_closed_connections_keep_forwarding_the_other_direction() -> Result<()> {
        // E.g. a client that sends its whole request and closes its sending side, and a server
        // that answers only then.
        let (mut peer_a, mut peer_b, forwarding) = spawn_forwarding(None);

        peer_a.write_all(b"request").await?;
        peer_a.shutdown().await?;
        let mut request = Vec::new();
        peer_b.read_to_end(&mut request).await?;
        assert_eq!(request, b"request");
        assert!(!forwarding.is_finished());

        peer_b.write_all(b"response").await?;
        peer_b.shutdown().await?;
        let mut response = Vec::new();
        peer_a.read_to_end(&mut response).await?;
        assert_eq!(response, b"response");

        let end = forwarding.await?;
        assert!(matches!(end, ForwardEnd::Completed), "{:?}", end);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn test_idle_timeout_ends_inactive_forwarding() -> Result<()> {
        let start = Instant::now();
        let (_peer_a, _peer_b, forwarding) = spawn_forwarding(Some(Duration::from_secs(10)));

        let end = forwarding.await?;

        assert!(matches!(end, ForwardEnd::Idle), "{:?}", end);
        assert!(start.elapsed() >= Duration::from_secs(10));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn test_data_transfer_resets_idle_timeout() -> Result<()> {
        let start = Instant::now();
        let (mut peer_a, mut peer_b, forwarding) = spawn_forwarding(Some(Duration::from_secs(10)));

        // Transfer a byte every 6 seconds, in alternating directions.
        let mut byte = [0u8; 1];
        for round in 0..4 {
            tokio::time::sleep(Duration::from_secs(6)).await;
            if round % 2 == 0 {
                peer_a.write_all(b"x").await?;
                peer_b.read_exact(&mut byte).await?;
            } else {
                peer_b.write_all(b"y").await?;
                peer_a.read_exact(&mut byte).await?;
            }
            assert!(!forwarding.is_finished(), "forwarding ended while active");
        }

        // Then stay idle: the forwarding ends 10 seconds after the last transfer.
        let end = forwarding.await?;
        assert!(matches!(end, ForwardEnd::Idle), "{:?}", end);
        assert!(start.elapsed() >= Duration::from_secs(24 + 10));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn test_one_way_transfer_keeps_forwarding_open() -> Result<()> {
        // E.g. a download: only one side sends, the other one only receives.
        for a_sends in [true, false] {
            let (mut peer_a, mut peer_b, forwarding) =
                spawn_forwarding(Some(Duration::from_secs(10)));
            let mut byte = [0u8; 1];
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_secs(6)).await;
                if a_sends {
                    peer_a.write_all(b"x").await?;
                    peer_b.read_exact(&mut byte).await?;
                } else {
                    peer_b.write_all(b"y").await?;
                    peer_a.read_exact(&mut byte).await?;
                }
                assert!(!forwarding.is_finished(), "forwarding ended while active");
            }
            forwarding.abort();
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn test_no_idle_timeout_without_limit() {
        let (_peer_a, _peer_b, forwarding) = spawn_forwarding(None);

        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;

        assert!(!forwarding.is_finished());
        forwarding.abort();
    }

    fn code(code: u32) -> quinn::VarInt {
        quinn::VarInt::from_u32(code)
    }

    #[test]
    fn test_how_the_peer_ended_a_quic_stream() {
        // The errors as quinn's streams return them, see quinn's From impls for io::Error.
        let cases: [(io::Error, QuicStreamEnd); 8] = [
            (
                quinn::WriteError::Stopped(code(0)).into(),
                QuicStreamEnd::Normal,
            ),
            (
                quinn::ReadError::Reset(code(0)).into(),
                QuicStreamEnd::Normal,
            ),
            (
                quinn::WriteError::Stopped(code(1)).into(),
                QuicStreamEnd::Aborted(StreamErrorCode::Aborted),
            ),
            (
                quinn::ReadError::Reset(code(2)).into(),
                QuicStreamEnd::Aborted(StreamErrorCode::ConnectFailed),
            ),
            (
                quinn::ReadError::Reset(code(7)).into(),
                QuicStreamEnd::Aborted(StreamErrorCode::Aborted),
            ),
            (quinn::WriteError::ClosedStream.into(), QuicStreamEnd::Lost),
            // Only quinn's error types count, not the message.
            (
                io::Error::other("sending stopped by peer: error 0"),
                QuicStreamEnd::Lost,
            ),
            (io::ErrorKind::ConnectionReset.into(), QuicStreamEnd::Lost),
        ];
        for (error, expected) in cases {
            assert_eq!(QuicStreamEnd::of(&error), expected, "{}", error);
        }
    }
}
