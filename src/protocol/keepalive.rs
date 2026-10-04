// PortRedirect Protocol Module - Keepalive on the control stream
//
// Once the tunnel is set up, the client sends PING and the server answers with PONG. Either side
// sends DRAIN when it shuts down, to announce that it starts no new forwarded connections. The
// message format is described in protocol::message and docs/PROTOCOL.md.
//
// License: GPL-3.0-only

use crate::protocol::close::CloseCode;
use crate::protocol::message::{Message, MessageStream, MessageType, ProtocolViolation};
use crate::shutdown::Shutdown;
use crate::PortRedirectProtocol;

use anyhow::{bail, Context, Result};
use std::convert::Infallible;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{interval, sleep_until, timeout_at, Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// The amount of time to wait for a PONG response before timing out.
const READ_TIMEOUT: Duration = PortRedirectProtocol::CONNECTION_KEEPALIVE_READ_TIMEOUT;
/// How often a PING is sent over the connection.
const KEEP_ALIVE_INTERVAL: Duration = PortRedirectProtocol::CONNECTION_KEEPALIVE_INTERVAL;
/// How long the server waits for the next message from the client: a PING is due every
/// `KEEP_ALIVE_INTERVAL`, and may take `READ_TIMEOUT` to arrive.
pub const CONTROL_CHANNEL_TIMEOUT: Duration = KEEP_ALIVE_INTERVAL.saturating_add(READ_TIMEOUT);

/// Runs the keepalive loop on the client side.
///
/// Every `KEEP_ALIVE_INTERVAL` the function sends a PING and then waits (up to `READ_TIMEOUT`)
/// for the PONG. When `shutdown` starts draining, it sends DRAIN, so the server stops listening
/// for new connections. A DRAIN from the server is logged.
/// It only returns when the keepalive fails: on a write error, an unexpected message, a closed
/// stream or a timeout. The error describes the failure.
pub async fn run_keepalive_client_loop<T>(
    control_stream: T,
    shutdown: Shutdown,
) -> Result<Infallible>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = MessageStream::new(control_stream);
    let mut tick_interval = interval(KEEP_ALIVE_INTERVAL);
    // When the PONG for the last PING is due, while waiting for it.
    let mut pong_deadline: Option<Instant> = None;
    let mut drain_sent = false;
    let mut pong_count = 0usize;

    loop {
        tokio::select! {
            biased;
            () = shutdown.draining(), if !drain_sent => {
                stream
                    .write(&Message::empty(MessageType::Drain))
                    .await
                    .context("failed to send DRAIN")?;
                info!("Told the server to start no new forwarded connections");
                drain_sent = true;
            }
            // Cancel safe, so sending a message doesn't lose one being read.
            message = stream.read() => match message.context("failed to read PONG")? {
                Some(message) => match message.kind {
                    MessageType::Pong if pong_deadline.is_some() => {
                        pong_deadline = None;
                        pong_count += 1;
                        debug!("Received PONG, count: {}", pong_count);
                    }
                    MessageType::Drain => {
                        info!("The server starts no new forwarded connections, e.g. because it is shutting down");
                    }
                    other => bail!(ProtocolViolation(format!(
                        "unexpected {:?} message on the control stream",
                        other
                    ))),
                },
                None => bail!("failed to read PONG: the control stream ended"),
            },
            () = sleep_until(pong_deadline.unwrap_or_else(Instant::now)), if pong_deadline.is_some() => {
                bail!("no PONG within {:?}", READ_TIMEOUT);
            }
            _ = tick_interval.tick(), if pong_deadline.is_none() => {
                stream
                    .write(&Message::empty(MessageType::Ping))
                    .await
                    .context("failed to send PING")?;
                debug!("Sent PING");
                pong_deadline = Some(Instant::now() + READ_TIMEOUT);
            }
        }
    }
}

/// Why the control channel loop of the server ended.
#[derive(Debug)]
pub enum ControlChannelEnd {
    /// The client ended the control stream, or the stream failed, e.g. because the connection
    /// was lost. The error is only logged, with `Debug`, which dead code analysis ignores.
    StreamClosed(#[allow(dead_code)] Option<anyhow::Error>),
    /// No message arrived in time.
    Timeout,
    /// The client sent an unexpected or invalid message.
    ProtocolViolation(String),
}

impl ControlChannelEnd {
    /// Returns the code to close the connection with.
    pub fn close_code(&self) -> CloseCode {
        match self {
            ControlChannelEnd::StreamClosed(_) => CloseCode::Ok,
            ControlChannelEnd::Timeout => CloseCode::KeepaliveFailed,
            ControlChannelEnd::ProtocolViolation(_) => CloseCode::ProtocolViolation,
        }
    }
}

/// Runs the control channel loop on the server side.
///
/// The server waits for messages from the client and answers each PING with a PONG. On DRAIN, it
/// cancels `listener_token`, which stops the TCP listener, and goes on. When `shutdown` starts
/// draining, it sends DRAIN to the client and cancels `listener_token`, too. The loop ends on an
/// unexpected message, a closed stream or when no message arrives within `timeout`, usually
/// [`CONTROL_CHANNEL_TIMEOUT`], and then cancels `listener_token`, too.
pub async fn run_control_channel_loop<T>(
    control_stream: T,
    listener_token: CancellationToken,
    shutdown: Shutdown,
    timeout: Duration,
) -> ControlChannelEnd
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = MessageStream::new(control_stream);
    let mut deadline = Instant::now() + timeout;
    let mut drain_sent = false;

    let end = loop {
        let read = tokio::select! {
            biased;
            () = shutdown.draining(), if !drain_sent => {
                drain_sent = true;
                info!("Shutting down, stopping the TCP listener and telling the client");
                listener_token.cancel();
                if let Err(e) = stream.write(&Message::empty(MessageType::Drain)).await {
                    debug!("Failed to send DRAIN: {:#}", e);
                    break ControlChannelEnd::StreamClosed(Some(e));
                }
                continue;
            }
            // Cancel safe, so sending DRAIN doesn't lose a message being read.
            read = timeout_at(deadline, stream.read()) => read,
        };
        let message = match read {
            Ok(Ok(Some(message))) => message,
            Ok(Ok(None)) => {
                debug!("Control stream closed by the client");
                break ControlChannelEnd::StreamClosed(None);
            }
            Ok(Err(e)) if e.is::<ProtocolViolation>() => {
                warn!("Invalid control message: {:#}", e);
                break ControlChannelEnd::ProtocolViolation(e.to_string());
            }
            Ok(Err(e)) => {
                debug!("Failed to read from control stream: {:#}", e);
                break ControlChannelEnd::StreamClosed(Some(e));
            }
            Err(_) => {
                warn!("Timed out waiting for PING message");
                break ControlChannelEnd::Timeout;
            }
        };
        deadline = Instant::now() + timeout;

        match message.kind {
            MessageType::Ping => {
                debug!("Received PING, sending PONG");
                let pong = Message::empty(MessageType::Pong);
                if let Err(e) = stream.write(&pong).await {
                    debug!("Failed to send PONG: {:#}", e);
                    break ControlChannelEnd::StreamClosed(Some(e));
                }
            }
            MessageType::Drain => {
                info!("The client starts no new forwarded connections, stopping the TCP listener");
                listener_token.cancel();
            }
            other => {
                warn!("Unexpected {:?} message on the control stream", other);
                break ControlChannelEnd::ProtocolViolation(format!(
                    "unexpected {:?} message",
                    other
                ));
            }
        }
    };

    debug!("Control channel loop ended, stopping the TCP listener");
    listener_token.cancel();
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio_test::io::Builder;

    // The tests run with paused time: when all tasks are idle, the clock jumps forward
    // to the next timer, so the real intervals and timeouts don't slow them down.
    // The mock streams panic on drop if not all expected reads and writes happened.

    const PING: &[u8] = &[3, 0, 0];
    const PONG: &[u8] = &[4, 0, 0];
    const DRAIN: &[u8] = &[5, 0, 0];

    /// A dummy stream that accepts all writes but never returns any data on read.
    struct NeverRead;
    impl AsyncRead for NeverRead {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }
    impl AsyncWrite for NeverRead {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn test_message_encodings() {
        // The tests' byte strings follow docs/PROTOCOL.md.
        for (bytes, kind) in [
            (PING, MessageType::Ping),
            (PONG, MessageType::Pong),
            (DRAIN, MessageType::Drain),
        ] {
            assert_eq!(bytes, [kind as u8, 0, 0]);
        }
    }

    // --- Client side: run_keepalive_client_loop ---

    /// Runs the client loop and returns its error message.
    async fn client_error<T: AsyncRead + AsyncWrite + Unpin>(stream: T) -> String {
        let Err(e) = run_keepalive_client_loop(stream, Shutdown::default()).await;
        format!("{:#}", e)
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_keeps_pinging_until_write_fails() {
        // Two successful rounds, then the third PING fails.
        let mock = Builder::new()
            .write(PING)
            .read(PONG)
            .write(PING)
            .read(PONG)
            .write_error(io::Error::other("connection lost"))
            .build();
        let error = client_error(mock).await;
        assert!(error.contains("failed to send PING"), "{}", error);
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_on_wrong_response() {
        let mock = Builder::new().write(PING).read(&[2, 0, 0]).build();
        let error = client_error(mock).await;
        assert!(
            error.contains("unexpected Welcome message on the control stream"),
            "{}",
            error
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_on_invalid_message() {
        // E.g. a client of protocol version 4, whose PONG started with "P".
        let mock = Builder::new().write(PING).read(b"P").build();
        let error = client_error(mock).await;
        assert!(error.contains("unknown message type 80"), "{}", error);
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_reads_pong_split_into_parts() {
        let mock = Builder::new()
            .write(PING)
            .read(&PONG[..1])
            .read(&PONG[1..])
            .write_error(io::Error::other("connection lost"))
            .build();
        let error = client_error(mock).await;
        assert!(error.contains("failed to send PING"), "{}", error);
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_accepts_drain_before_pong() {
        let mock = Builder::new()
            .write(PING)
            .read(DRAIN)
            .read(PONG)
            .write(PING)
            .read(PONG)
            .write_error(io::Error::other("connection lost"))
            .build();
        let error = client_error(mock).await;
        assert!(error.contains("failed to send PING"), "{}", error);
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_on_pong_without_ping() {
        let mock = Builder::new().write(PING).read(PONG).read(PONG).build();
        let error = client_error(mock).await;
        assert!(
            error.contains("unexpected Pong message on the control stream"),
            "{}",
            error
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_sends_drain_when_shutting_down() {
        let (mut server_side, client_side) = duplex(64);
        let shutdown = Shutdown::default();
        let client = tokio::spawn(run_keepalive_client_loop(client_side, shutdown.clone()));

        let mut message = [0u8; 3];
        server_side.read_exact(&mut message).await.unwrap();
        assert_eq!(message, PING);
        // Also while the client waits for the PONG.
        shutdown.drain();
        server_side.read_exact(&mut message).await.unwrap();
        assert_eq!(message, DRAIN);

        // The client keeps the connection alive for the running connections.
        server_side.write_all(PONG).await.unwrap();
        server_side.read_exact(&mut message).await.unwrap();
        assert_eq!(message, PING);
        server_side.write_all(PONG).await.unwrap();
        // DRAIN only once.
        server_side.read_exact(&mut message).await.unwrap();
        assert_eq!(message, PING);
        assert!(!client.is_finished());

        drop(server_side);
        let Err(e) = client.await.unwrap();
        assert!(
            format!("{:#}", e).contains("failed to read PONG"),
            "{:#}",
            e
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_when_drain_fails() {
        let shutdown = Shutdown::default();
        shutdown.drain();
        let mock = Builder::new()
            .write_error(io::Error::other("connection lost"))
            .build();
        let Err(e) = run_keepalive_client_loop(mock, shutdown).await;
        assert!(
            format!("{:#}", e).contains("failed to send DRAIN"),
            "{:#}",
            e
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_when_connection_closes() {
        // After the PING, the read returns EOF.
        let mock = Builder::new().write(PING).build();
        let error = client_error(mock).await;
        assert!(error.contains("failed to read PONG"), "{}", error);
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_on_truncated_pong() {
        let mock = Builder::new().write(PING).read(&PONG[..2]).build();
        let error = client_error(mock).await;
        assert!(error.contains("failed to read PONG"), "{}", error);
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_on_pong_timeout() {
        let start = tokio::time::Instant::now();
        let error = client_error(NeverRead).await;
        assert!(error.contains("no PONG"), "{}", error);
        assert!(start.elapsed() >= READ_TIMEOUT);
    }

    // --- Server side: run_control_channel_loop ---

    #[tokio::test(start_paused = true)]
    async fn test_server_answers_pings_until_the_stream_ends() {
        let mock = Builder::new()
            .read(PING)
            .write(PONG)
            .read(PING)
            .write(PONG)
            .build();
        let listener_token = CancellationToken::new();

        let end = run_control_channel_loop(
            mock,
            listener_token.clone(),
            Shutdown::default(),
            CONTROL_CHANNEL_TIMEOUT,
        )
        .await;

        assert!(
            matches!(end, ControlChannelEnd::StreamClosed(None)),
            "{:?}",
            end
        );
        assert_eq!(end.close_code(), CloseCode::Ok);
        assert!(listener_token.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_listener_on_drain_and_goes_on() {
        let (mut client_side, server_side) = duplex(64);
        let listener_token = CancellationToken::new();
        let server = tokio::spawn(run_control_channel_loop(
            server_side,
            listener_token.clone(),
            Shutdown::default(),
            CONTROL_CHANNEL_TIMEOUT,
        ));

        client_side.write_all(DRAIN).await.unwrap();
        listener_token.cancelled().await;

        // The tunnel stays up for the running connections.
        client_side.write_all(PING).await.unwrap();
        let mut pong = [0u8; 3];
        client_side.read_exact(&mut pong).await.unwrap();
        assert_eq!(pong, PONG);
        assert!(!server.is_finished());

        drop(client_side);
        let end = server.await.unwrap();
        assert_eq!(end.close_code(), CloseCode::Ok);
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_sends_drain_when_shutting_down() {
        let (mut client_side, server_side) = duplex(64);
        let listener_token = CancellationToken::new();
        let shutdown = Shutdown::default();
        let server = tokio::spawn(run_control_channel_loop(
            server_side,
            listener_token.clone(),
            shutdown.clone(),
            CONTROL_CHANNEL_TIMEOUT,
        ));

        // The server drains while it reads a PING, which doesn't get lost.
        client_side.write_all(&PING[..1]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
        shutdown.drain();
        let mut message = [0u8; 3];
        client_side.read_exact(&mut message).await.unwrap();
        assert_eq!(message, DRAIN);
        assert!(listener_token.is_cancelled());

        // The tunnel stays up for the running connections.
        client_side.write_all(&PING[1..]).await.unwrap();
        client_side.read_exact(&mut message).await.unwrap();
        assert_eq!(message, PONG);
        assert!(!server.is_finished());

        drop(client_side);
        let end = server.await.unwrap();
        assert_eq!(end.close_code(), CloseCode::Ok);
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_when_drain_fails() {
        let shutdown = Shutdown::default();
        shutdown.drain();
        let mock = Builder::new()
            .write_error(io::Error::other("connection lost"))
            .build();
        let end = run_control_channel_loop(
            mock,
            CancellationToken::new(),
            shutdown,
            CONTROL_CHANNEL_TIMEOUT,
        )
        .await;
        assert!(
            matches!(&end, ControlChannelEnd::StreamClosed(Some(_))),
            "{:?}",
            end
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_on_unexpected_message() {
        let mock = Builder::new().read(&[1, 0, 0]).build();
        let listener_token = CancellationToken::new();

        let end = run_control_channel_loop(
            mock,
            listener_token.clone(),
            Shutdown::default(),
            CONTROL_CHANNEL_TIMEOUT,
        )
        .await;

        assert!(
            matches!(&end, ControlChannelEnd::ProtocolViolation(m) if m.contains("unexpected Hello")),
            "{:?}",
            end
        );
        assert_eq!(end.close_code(), CloseCode::ProtocolViolation);
        assert!(listener_token.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_on_invalid_message() {
        // Unknown type, and a message longer than allowed.
        for bytes in [&b"P"[..], &[3, 0xff, 0xff]] {
            let mock = Builder::new().read(bytes).build();
            let end = run_control_channel_loop(
                mock,
                CancellationToken::new(),
                Shutdown::default(),
                CONTROL_CHANNEL_TIMEOUT,
            )
            .await;
            assert!(
                matches!(&end, ControlChannelEnd::ProtocolViolation(_)),
                "{:?}: {:?}",
                bytes,
                end
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_ignores_payload_of_ping() {
        let mock = Builder::new()
            .read(&[3, 0, 2, 0xaa, 0xbb])
            .write(PONG)
            .build();
        let end = run_control_channel_loop(
            mock,
            CancellationToken::new(),
            Shutdown::default(),
            CONTROL_CHANNEL_TIMEOUT,
        )
        .await;
        assert!(
            matches!(end, ControlChannelEnd::StreamClosed(None)),
            "{:?}",
            end
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_reads_messages_split_into_parts() {
        let mock = Builder::new()
            .read(&PING[..1])
            .read(&PING[1..])
            .write(PONG)
            .build();

        let end = run_control_channel_loop(
            mock,
            CancellationToken::new(),
            Shutdown::default(),
            CONTROL_CHANNEL_TIMEOUT,
        )
        .await;

        assert!(
            matches!(end, ControlChannelEnd::StreamClosed(None)),
            "{:?}",
            end
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_reads_several_messages_at_once() {
        let (mut client_side, server_side) = duplex(64);
        let server = tokio::spawn(run_control_channel_loop(
            server_side,
            CancellationToken::new(),
            Shutdown::default(),
            CONTROL_CHANNEL_TIMEOUT,
        ));

        client_side.write_all(&PING.repeat(2)).await.unwrap();
        let mut pongs = [0u8; 2 * PONG.len()];
        client_side.read_exact(&mut pongs).await.unwrap();
        drop(client_side);

        assert_eq!(pongs.as_slice(), PONG.repeat(2));
        let end = server.await.unwrap();
        assert!(
            matches!(end, ControlChannelEnd::StreamClosed(None)),
            "{:?}",
            end
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_on_truncated_message() {
        let mock = Builder::new().read(&PING[..2]).build();

        let end = run_control_channel_loop(
            mock,
            CancellationToken::new(),
            Shutdown::default(),
            CONTROL_CHANNEL_TIMEOUT,
        )
        .await;

        assert!(
            matches!(&end, ControlChannelEnd::StreamClosed(Some(_))),
            "{:?}",
            end
        );
        assert_eq!(end.close_code(), CloseCode::Ok);
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_when_pong_fails() {
        let mock = Builder::new()
            .read(PING)
            .write_error(io::Error::other("connection lost"))
            .build();

        let end = run_control_channel_loop(
            mock,
            CancellationToken::new(),
            Shutdown::default(),
            CONTROL_CHANNEL_TIMEOUT,
        )
        .await;

        assert!(
            matches!(&end, ControlChannelEnd::StreamClosed(Some(_))),
            "{:?}",
            end
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_without_pings() {
        let listener_token = CancellationToken::new();
        let start = tokio::time::Instant::now();

        let end = run_control_channel_loop(
            NeverRead,
            listener_token.clone(),
            Shutdown::default(),
            CONTROL_CHANNEL_TIMEOUT,
        )
        .await;

        assert!(matches!(end, ControlChannelEnd::Timeout), "{:?}", end);
        assert_eq!(end.close_code(), CloseCode::KeepaliveFailed);
        assert!(start.elapsed() >= KEEP_ALIVE_INTERVAL + READ_TIMEOUT);
        assert!(listener_token.is_cancelled());
    }

    // --- Both sides together ---

    #[tokio::test(start_paused = true)]
    async fn test_client_and_server_keep_connection_alive() {
        let (client_side, server_side) = duplex(64);
        let listener_token = CancellationToken::new();
        let server = tokio::spawn(run_control_channel_loop(
            server_side,
            listener_token.clone(),
            Shutdown::default(),
            CONTROL_CHANNEL_TIMEOUT,
        ));

        // Run the client much longer than the server's PING timeout.
        let client_runtime = (KEEP_ALIVE_INTERVAL + READ_TIMEOUT) * 3;
        let client = tokio::time::timeout(
            client_runtime,
            run_keepalive_client_loop(client_side, Shutdown::default()),
        );
        assert!(client.await.is_err(), "client loop ended early");
        assert!(
            !listener_token.is_cancelled(),
            "server ended the connection although the client sent PINGs"
        );

        // The client is gone now, so the server ends the connection.
        let end = server.await.unwrap();
        assert!(
            matches!(end, ControlChannelEnd::StreamClosed(_)),
            "{:?}",
            end
        );
        assert!(listener_token.is_cancelled());
    }
}
