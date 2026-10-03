// PortRedirect
//
// License: GPL-3.0-only

use anyhow::{Context, Result};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;
use tracing::info;

use crate::metrics_helper::MetricsCounter;

/// Forwards data bidirectionally between two asynchronous streams.
///
/// This function copies data between two streams concurrently using a fixed buffer size defined by
/// `PortRedirectProtocol::QUIC_STREAM_READ_BUFFER_SIZE`. As data is transferred, the provided counters
/// are incremented by the number of bytes forwarded in each direction. If the copy completes without
/// errors, the function returns `Ok(())`. If an error occurs, it is wrapped with additional context.
/// However, if the error message contains `"error 0"`, this is interpreted as a graceful shutdown,
/// and the function returns success.
///
/// # Parameters
///
/// - `a`: A mutable reference to the first stream implementing both `AsyncRead` and `AsyncWrite`.
/// - `b`: A mutable reference to the second stream implementing both `AsyncRead` and `AsyncWrite`.
/// - `id`: A stream identifier (displayable) used for logging purposes.
/// - `stream_a_counter`: A counter that is incremented by the number of bytes read from stream A.
/// - `stream_b_counter`: A counter that is incremented by the number of bytes read from stream B.
/// - `idle_timeout`: If set, forwarding stops when no data was transferred in either direction
///   for this long. This counts as a normal end and returns `Ok(())`.
///
/// # Returns
///
/// Returns `Ok(())` if the bidirectional copy completes (or a graceful shutdown or idle timeout is
/// detected), or an error wrapped with context if a non-graceful error occurs.
///
/// # Errors
///
/// If the underlying I/O operations fail with an error that does **not** contain `"error 0"` in its
/// description, an error with additional context `"Bidirectional copy failed"` is returned.
///
/// # Examples
///
/// ```no_run
/// # use portredirect::forward::forward_bidirectional;
/// # use portredirect::metrics_helper::DummyCounter;
/// # use tokio::io::{duplex, AsyncRead, AsyncWrite};
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// let (mut a, mut b) = duplex(64);
/// let counter_a = DummyCounter::new();
/// let counter_b = DummyCounter::new();
/// forward_bidirectional(&mut a, &mut b, "stream1", &counter_a, &counter_b, None).await?;
/// # Ok(())
/// # }
/// ```
pub async fn forward_bidirectional<StreamA, StreamB, StreamName, CounterA, CounterB>(
    a: &mut StreamA,
    b: &mut StreamB,
    id: StreamName,
    stream_a_counter: CounterA,
    stream_b_counter: CounterB,
    idle_timeout: Option<Duration>,
) -> Result<()>
where
    StreamA: AsyncRead + AsyncWrite + Unpin,
    StreamB: AsyncRead + AsyncWrite + Unpin,
    StreamName: std::fmt::Display,
    CounterA: MetricsCounter,
    CounterB: MetricsCounter,
{
    let activity = Activity::new();
    let mut a = Tracked::new(a, &activity, &stream_a_counter);
    let mut b = Tracked::new(b, &activity, &stream_b_counter);

    let buf_size = crate::PortRedirectProtocol::QUIC_STREAM_READ_BUFFER_SIZE;
    let copy = copy_bidirectional_with_sizes(&mut a, &mut b, buf_size, buf_size);
    let result = match idle_timeout {
        Some(idle_timeout) => tokio::select! {
            result = copy => result.map(Some),
            () = activity.idle_for(idle_timeout) => Ok(None),
        },
        None => copy.await.map(Some),
    };

    match result {
        Ok(Some(_)) => {
            info!(
                "Stream (id={}): forwarded (A:B) ({}:{}) bytes",
                id, a.bytes_read, b.bytes_read
            );
            Ok(())
        }
        Ok(None) => {
            info!(
                "Stream (id={}): closed after {:?} without data transfer, forwarded (A:B) ({}:{}) bytes",
                id,
                idle_timeout.unwrap_or_default(),
                a.bytes_read,
                b.bytes_read
            );
            Ok(())
        }
        Err(err) => {
            // If the error indicates a graceful shutdown, log it and return success.
            if err.to_string().contains("error 0") {
                info!("Stream (id={}): graceful shutdown detected: {}", id, err);
                Ok(())
            } else {
                Err(err).context("Bidirectional copy failed")
            }
        }
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

/// Wraps a stream to count the bytes read from it and to record the activity.
struct Tracked<'a, S, C> {
    inner: &'a mut S,
    activity: &'a Activity,
    counter: &'a C,
    bytes_read: u64,
}

impl<'a, S, C> Tracked<'a, S, C> {
    fn new(inner: &'a mut S, activity: &'a Activity, counter: &'a C) -> Self {
        Self {
            inner,
            activity,
            counter,
            bytes_read: 0,
        }
    }
}

impl<S: AsyncRead + Unpin, C: MetricsCounter> AsyncRead for Tracked<'_, S, C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        let result = Pin::new(&mut *this.inner).poll_read(cx, buf);
        let bytes = (buf.filled().len() - filled_before) as u64;
        if bytes > 0 {
            this.bytes_read += bytes;
            this.counter.inc_by(bytes);
            this.activity.record_transfer();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin, C> AsyncWrite for Tracked<'_, S, C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics_helper::DummyCounter;
    use anyhow::Result;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// A simple in-memory test stream that has a read buffer and collects written data.
    #[derive(Debug)]
    struct TestStream {
        /// Data that will be "read" from this stream.
        read_data: Vec<u8>,
        /// Data that has been "written" to this stream.
        write_data: Vec<u8>,
        /// Current read position.
        pos: usize,
    }

    impl TestStream {
        fn new(initial_data: &[u8]) -> Self {
            Self {
                read_data: initial_data.to_vec(),
                write_data: Vec::new(),
                pos: 0,
            }
        }
    }

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            let remaining = &self.read_data[self.pos..];
            if remaining.is_empty() {
                // Signal EOF by not filling any new data.
                return Poll::Ready(Ok(()));
            }
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            self.write_data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A stream that fails immediately when read or written.
    struct FailingStream;

    impl AsyncRead for FailingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Err(std::io::Error::other("read failure")))
        }
    }

    impl AsyncWrite for FailingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Poll::Ready(Err(std::io::Error::other("write failure")))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_forward_bidirectional_success() -> Result<()> {
        // Stream A will "send" the bytes in "hello" and expect to receive data from B.
        let mut stream_a = TestStream::new(b"hello");
        // Stream B will "send" the bytes in "world" and expect to receive data from A.
        let mut stream_b = TestStream::new(b"world");

        // Create dummy counters for both directions.
        let dummy_counter_a = DummyCounter::new();
        let dummy_counter_b = DummyCounter::new();

        // Run the forwarding function.
        forward_bidirectional(
            &mut stream_a,
            &mut stream_b,
            "A",
            &dummy_counter_a,
            &dummy_counter_b,
            None,
        )
        .await?;

        // After bidirectional copy, stream_a should have received stream_b's data, and vice versa.
        assert_eq!(stream_a.write_data, b"world");
        assert_eq!(stream_b.write_data, b"hello");
        assert_eq!(dummy_counter_a.get(), 5);
        assert_eq!(dummy_counter_b.get(), 5);

        Ok(())
    }

    #[tokio::test]
    async fn test_forward_bidirectional_failure() {
        let mut normal_stream = TestStream::new(b"data");
        let mut failing_stream = FailingStream;

        // Create dummy counters for both directions.
        let dummy_counter_a = DummyCounter::new();
        let dummy_counter_b = DummyCounter::new();

        // One of the streams will immediately fail; our function should return an error with the proper context.
        let result = forward_bidirectional(
            &mut failing_stream,
            &mut normal_stream,
            "fail",
            &dummy_counter_a,
            &dummy_counter_b,
            None,
        )
        .await;
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.err().unwrap());
        assert!(
            err_msg.contains("Bidirectional copy failed"),
            "Error message did not contain expected context, got: {}",
            err_msg
        );
    }

    /// A stream that simulates a graceful shutdown error by returning errors containing "error 0".
    struct GracefulStream;

    impl AsyncRead for GracefulStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Err(std::io::Error::other(
                "sending stopped by peer: error 0",
            )))
        }
    }

    impl AsyncWrite for GracefulStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Poll::Ready(Err(std::io::Error::other(
                "sending stopped by peer: error 0",
            )))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_forward_bidirectional_graceful_shutdown() -> Result<()> {
        // Use a normal TestStream for one side.
        let mut normal_stream = TestStream::new(b"normal");
        // Use the graceful stream for the other side.
        let mut graceful_stream = GracefulStream;

        // Create dummy counters for both directions.
        let dummy_counter_a = DummyCounter::new();
        let dummy_counter_b = DummyCounter::new();

        // When one side produces an error containing "error 0", our forward_bidirectional
        // function should treat it as a graceful shutdown and return Ok(()).
        forward_bidirectional(
            &mut normal_stream,
            &mut graceful_stream,
            "normal",
            &dummy_counter_a,
            &dummy_counter_b,
            None,
        )
        .await?;

        Ok(())
    }

    /// Runs `forward_bidirectional` between the inner ends of two duplex pipes and returns the
    /// outer ends, which play the two peers.
    fn spawn_forwarding(
        idle_timeout: Option<Duration>,
    ) -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (peer_a, mut inner_a) = tokio::io::duplex(1024);
        let (peer_b, mut inner_b) = tokio::io::duplex(1024);
        let forwarding = tokio::spawn(async move {
            let counter_a = DummyCounter::new();
            let counter_b = DummyCounter::new();
            forward_bidirectional(
                &mut inner_a,
                &mut inner_b,
                "idle",
                &counter_a,
                &counter_b,
                idle_timeout,
            )
            .await
        });
        (peer_a, peer_b, forwarding)
    }

    #[tokio::test(start_paused = true)]
    async fn test_idle_timeout_ends_inactive_forwarding() -> Result<()> {
        let start = Instant::now();
        let (_peer_a, _peer_b, forwarding) = spawn_forwarding(Some(Duration::from_secs(10)));

        forwarding.await??;

        assert!(start.elapsed() >= Duration::from_secs(10));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn test_data_transfer_resets_idle_timeout() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        forwarding.await??;
        assert!(start.elapsed() >= Duration::from_secs(24 + 10));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn test_no_idle_timeout_without_limit() {
        let (_peer_a, _peer_b, forwarding) = spawn_forwarding(None);

        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;

        assert!(!forwarding.is_finished());
        forwarding.abort();
    }
}
