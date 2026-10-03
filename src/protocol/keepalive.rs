use crate::protocol::close::CloseCode;
use crate::PortRedirectProtocol;

use anyhow::{anyhow, Context, Result};
use std::convert::Infallible;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{interval, timeout, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// The amount of time to wait for a PONG response before timing out.
const READ_TIMEOUT: Duration = PortRedirectProtocol::CONNECTION_KEEPALIVE_READ_TIMEOUT;
/// How often a PING is sent over the connection.
const KEEP_ALIVE_INTERVAL: Duration = PortRedirectProtocol::CONNECTION_KEEPALIVE_INTERVAL;
/// The PING message sent to the remote peer.
const PING_MESSAGE: &[u8] = b"PING\n";
/// The expected PONG response from the remote peer.
const PONG_MESSAGE: &[u8] = b"PONG\n";
/// Message from client to server that initiates connection teardown.
const CONNECTION_END_MESSAGE: &[u8] = b"BYE\n";
/// Maximum length of a control message the server accepts, including the newline.
const MAX_CONTROL_MESSAGE_LENGTH: usize = 16;

/// Runs the keepalive loop on the client side.
///
/// Every `KEEP_ALIVE_INTERVAL` the function sends a PING message, flushes the stream,
/// and then waits (up to `READ_TIMEOUT`) for the PONG response.
/// It only returns when the keepalive fails: on a write error, an unexpected response,
/// a closed stream or a timeout. The error describes the failure.
pub async fn run_keepalive_client_loop<T>(mut control_stream: T) -> Result<Infallible>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut tick_interval = interval(KEEP_ALIVE_INTERVAL);
    let mut pong_count = 0usize;

    loop {
        // Wait for the next tick.
        tick_interval.tick().await;

        // Send the PING message.
        control_stream
            .write_all(PING_MESSAGE)
            .await
            .context("failed to send PING")?;
        control_stream
            .flush()
            .await
            .context("failed to flush PING")?;
        debug!("Sent PING");

        // Read the PONG response with a timeout.
        let mut response = [0u8; PONG_MESSAGE.len()];
        timeout(READ_TIMEOUT, control_stream.read_exact(&mut response))
            .await
            .map_err(|_| anyhow!("no PONG within {:?}", READ_TIMEOUT))?
            .context("failed to read PONG")?;
        if response != PONG_MESSAGE {
            return Err(anyhow!(
                "unexpected keepalive response {:?}",
                String::from_utf8_lossy(&response)
            ));
        }
        pong_count += 1;
        debug!("Received PONG, count: {}", pong_count);
    }
}

/// Why the control channel loop of the server ended.
#[derive(Debug)]
pub enum ControlChannelEnd {
    /// The cancellation token was triggered.
    Cancelled,
    /// The client ended the tunnel with BYE.
    ClientSaidBye,
    /// The stream ended or failed, e.g. because the connection was lost.
    StreamClosed(Option<io::Error>),
    /// No message arrived in time.
    Timeout,
    /// The client sent an unexpected or too long message.
    UnexpectedMessage(Vec<u8>),
}

impl ControlChannelEnd {
    /// Returns the code to close the connection with.
    pub fn close_code(&self) -> CloseCode {
        match self {
            ControlChannelEnd::Cancelled
            | ControlChannelEnd::ClientSaidBye
            | ControlChannelEnd::StreamClosed(_) => CloseCode::Ok,
            ControlChannelEnd::Timeout => CloseCode::KeepaliveFailed,
            ControlChannelEnd::UnexpectedMessage(_) => CloseCode::ProtocolViolation,
        }
    }
}

/// Runs the control channel loop on the server side.
///
/// The server waits for incoming PING messages from the client and answers each with a PONG.
/// The loop ends on BYE, cancellation, an unexpected message, a timeout or a closed stream,
/// and cancels `cancel_token` when it ends.
pub async fn run_control_channel_loop<T>(
    mut control_stream: T,
    cancel_token: CancellationToken,
) -> ControlChannelEnd
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let end = loop {
        let message = tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("Cancellation token triggered in control channel loop");
                break ControlChannelEnd::Cancelled;
            }
            message = timeout(KEEP_ALIVE_INTERVAL + READ_TIMEOUT, read_control_message(&mut control_stream)) => message,
        };

        let message = match message {
            Ok(Ok(Some(message))) => message,
            Ok(Ok(None)) => {
                debug!("Control stream closed by the client");
                break ControlChannelEnd::StreamClosed(None);
            }
            Ok(Err(e)) => {
                debug!("Failed to read from control stream: {}", e);
                break ControlChannelEnd::StreamClosed(Some(e));
            }
            Err(_) => {
                warn!("Timed out waiting for PING message");
                break ControlChannelEnd::Timeout;
            }
        };

        if message == PING_MESSAGE {
            debug!("Received PING, sending PONG");
            let sent = match control_stream.write_all(PONG_MESSAGE).await {
                Ok(()) => control_stream.flush().await,
                Err(e) => Err(e),
            };
            if let Err(e) = sent {
                debug!("Failed to send PONG: {}", e);
                break ControlChannelEnd::StreamClosed(Some(e));
            }
        } else if message == CONNECTION_END_MESSAGE {
            info!("Received BYE, initiating client connection shutdown");
            break ControlChannelEnd::ClientSaidBye;
        } else {
            warn!("Unexpected control message received: {:?}", message);
            break ControlChannelEnd::UnexpectedMessage(message);
        }
    };

    debug!("Control channel loop ended, cancelling token");
    cancel_token.cancel();
    end
}

/// Reads a newline-terminated control message of at most `MAX_CONTROL_MESSAGE_LENGTH` bytes.
///
/// Returns `None` if the stream ended before the first byte. A longer message is returned
/// truncated, without its newline, so it never matches a valid message.
async fn read_control_message<T>(stream: &mut T) -> io::Result<Option<Vec<u8>>>
where
    T: AsyncRead + Unpin,
{
    let mut message = Vec::with_capacity(MAX_CONTROL_MESSAGE_LENGTH);
    let mut byte = [0u8; 1];
    while message.len() < MAX_CONTROL_MESSAGE_LENGTH {
        if stream.read(&mut byte).await? == 0 {
            if message.is_empty() {
                return Ok(None);
            }
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        message.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(Some(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio::io::duplex;
    use tokio_test::io::Builder;

    // The tests run with paused time: when all tasks are idle, the clock jumps forward
    // to the next timer, so the real intervals and timeouts don't slow them down.
    // The mock streams panic on drop if not all expected reads and writes happened.

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

    // --- Client side: run_keepalive_client_loop ---

    /// Runs the client loop and returns its error message.
    async fn client_error<T: AsyncRead + AsyncWrite + Unpin>(stream: T) -> String {
        let Err(e) = run_keepalive_client_loop(stream).await;
        format!("{:#}", e)
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_keeps_pinging_until_write_fails() {
        // Two successful rounds, then the third PING fails.
        let mock = Builder::new()
            .write(PING_MESSAGE)
            .read(PONG_MESSAGE)
            .write(PING_MESSAGE)
            .read(PONG_MESSAGE)
            .write_error(io::Error::other("connection lost"))
            .build();
        let error = client_error(mock).await;
        assert!(error.contains("failed to send PING"), "{}", error);
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_on_wrong_response() {
        let mock = Builder::new().write(PING_MESSAGE).read(b"WRONG").build();
        let error = client_error(mock).await;
        assert!(error.contains("unexpected keepalive response"), "{}", error);
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_reads_pong_split_into_parts() {
        let mock = Builder::new()
            .write(PING_MESSAGE)
            .read(b"PO")
            .read(b"NG\n")
            .write_error(io::Error::other("connection lost"))
            .build();
        let error = client_error(mock).await;
        assert!(error.contains("failed to send PING"), "{}", error);
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_when_connection_closes() {
        // After the PING, the read returns EOF.
        let mock = Builder::new().write(PING_MESSAGE).build();
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
    async fn test_server_answers_pings_until_bye() {
        let mock = Builder::new()
            .read(PING_MESSAGE)
            .write(PONG_MESSAGE)
            .read(PING_MESSAGE)
            .write(PONG_MESSAGE)
            .read(CONNECTION_END_MESSAGE)
            .build();
        let cancel_token = CancellationToken::new();

        let end = run_control_channel_loop(mock, cancel_token.clone()).await;

        assert!(matches!(end, ControlChannelEnd::ClientSaidBye), "{:?}", end);
        assert_eq!(end.close_code(), CloseCode::Ok);
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_on_unexpected_message() {
        let mock = Builder::new().read(b"HELLO\n").build();
        let cancel_token = CancellationToken::new();

        let end = run_control_channel_loop(mock, cancel_token.clone()).await;

        assert!(
            matches!(&end, ControlChannelEnd::UnexpectedMessage(m) if m == b"HELLO\n"),
            "{:?}",
            end
        );
        assert_eq!(end.close_code(), CloseCode::ProtocolViolation);
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_on_too_long_message() {
        let mock = Builder::new()
            .read(&[b'P'; MAX_CONTROL_MESSAGE_LENGTH])
            .build();

        let end = run_control_channel_loop(mock, CancellationToken::new()).await;

        assert!(
            matches!(&end, ControlChannelEnd::UnexpectedMessage(m) if m.len() == MAX_CONTROL_MESSAGE_LENGTH),
            "{:?}",
            end
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_reads_messages_split_into_parts() {
        let mock = Builder::new()
            .read(b"PI")
            .read(b"NG\n")
            .write(PONG_MESSAGE)
            .read(b"B")
            .read(b"YE\n")
            .build();

        let end = run_control_channel_loop(mock, CancellationToken::new()).await;

        assert!(matches!(end, ControlChannelEnd::ClientSaidBye), "{:?}", end);
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_reads_several_messages_at_once() {
        let (mut client_side, server_side) = duplex(64);
        let server = tokio::spawn(run_control_channel_loop(
            server_side,
            CancellationToken::new(),
        ));

        client_side.write_all(b"PING\nPING\nBYE\n").await.unwrap();
        let mut pongs = [0u8; 2 * PONG_MESSAGE.len()];
        client_side.read_exact(&mut pongs).await.unwrap();

        assert_eq!(pongs.as_slice(), PONG_MESSAGE.repeat(2));
        let end = server.await.unwrap();
        assert!(matches!(end, ControlChannelEnd::ClientSaidBye), "{:?}", end);
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_on_truncated_message() {
        let mock = Builder::new().read(b"PI").build();

        let end = run_control_channel_loop(mock, CancellationToken::new()).await;

        assert!(
            matches!(&end, ControlChannelEnd::StreamClosed(Some(e)) if e.kind() == io::ErrorKind::UnexpectedEof),
            "{:?}",
            end
        );
        assert_eq!(end.close_code(), CloseCode::Ok);
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_when_connection_closes() {
        let mock = Builder::new()
            .read(PING_MESSAGE)
            .write(PONG_MESSAGE)
            .build();
        let cancel_token = CancellationToken::new();

        let end = run_control_channel_loop(mock, cancel_token.clone()).await;

        assert!(
            matches!(end, ControlChannelEnd::StreamClosed(None)),
            "{:?}",
            end
        );
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_without_pings() {
        let cancel_token = CancellationToken::new();
        let start = tokio::time::Instant::now();

        let end = run_control_channel_loop(NeverRead, cancel_token.clone()).await;

        assert!(matches!(end, ControlChannelEnd::Timeout), "{:?}", end);
        assert_eq!(end.close_code(), CloseCode::KeepaliveFailed);
        assert!(start.elapsed() >= KEEP_ALIVE_INTERVAL + READ_TIMEOUT);
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_when_cancelled() {
        let cancel_token = CancellationToken::new();
        cancel_token.cancel();

        // Returns immediately, without reading anything.
        let end = run_control_channel_loop(NeverRead, cancel_token).await;
        assert!(matches!(end, ControlChannelEnd::Cancelled), "{:?}", end);
    }

    // --- Both sides together ---

    #[tokio::test(start_paused = true)]
    async fn test_client_and_server_keep_connection_alive() {
        let (client_side, server_side) = duplex(64);
        let cancel_token = CancellationToken::new();
        let server = tokio::spawn(run_control_channel_loop(server_side, cancel_token.clone()));

        // Run the client much longer than the server's PING timeout.
        let client_runtime = (KEEP_ALIVE_INTERVAL + READ_TIMEOUT) * 3;
        let client = tokio::time::timeout(client_runtime, run_keepalive_client_loop(client_side));
        assert!(client.await.is_err(), "client loop ended early");
        assert!(
            !cancel_token.is_cancelled(),
            "server ended the connection although the client sent PINGs"
        );

        // The client is gone now, so the server ends the connection.
        let end = server.await.unwrap();
        assert!(
            matches!(end, ControlChannelEnd::StreamClosed(_)),
            "{:?}",
            end
        );
        assert!(cancel_token.is_cancelled());
    }
}
