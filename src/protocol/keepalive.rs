use crate::PortRedirectProtocol;

use anyhow::{Error, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
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

/// Runs the keepalive loop on the client side.
///
/// Every `KEEP_ALIVE_INTERVAL` the function sends a PING message, flushes the stream,
/// and then waits (up to `READ_TIMEOUT`) for a newline-terminated response.
/// If the response exactly matches `PONG_MESSAGE` the ping is considered successful.
/// Any error (write/flush error, unexpected response, connection close, or timeout)
/// causes the loop to exit gracefully.
pub async fn run_keepalive_client_loop<T>(mut auth_stream: T) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut tick_interval = interval(KEEP_ALIVE_INTERVAL);
    let mut pong_count = 0usize;

    loop {
        // Wait for the next tick.
        tick_interval.tick().await;

        // Send the PING message.
        if let Err(e) = auth_stream.write_all(PING_MESSAGE).await {
            warn!("Failed to send PING: {}", e);
            break;
        }
        if let Err(e) = auth_stream.flush().await {
            warn!("Failed to flush PING: {}", e);
            break;
        }
        info!("Sent PING");

        // Read the PONG response with a timeout.
        let mut response_buf = Vec::with_capacity(16);
        let mut reader = BufReader::new(&mut auth_stream);
        match timeout(READ_TIMEOUT, reader.read_until(b'\n', &mut response_buf)).await {
            Ok(Ok(0)) => {
                warn!("Connection closed by remote during keepalive");
                break;
            }
            Ok(Ok(_)) => {
                if response_buf == PONG_MESSAGE {
                    pong_count += 1;
                    info!("Received PONG, count: {}", pong_count);
                } else {
                    warn!("Unexpected response: {:?}", response_buf);
                    break;
                }
            }
            Ok(Err(e)) => {
                warn!("Failed to read PONG: {:?}", e);
                break;
            }
            Err(_) => {
                warn!("Timed out waiting for PONG response");
                break;
            }
        }
    }

    Ok(())
}

/// Runs the keepalive loop on the server side.
///
/// Instead of sending periodic PING messages, the server now waits for
/// incoming PING messages from the remote peer. When a PING is received,
/// the server replies with a PONG. Any error (read/write, unexpected message,
/// timeout, or connection close) causes the loop to exit gracefully.
///
/// Runs the keepalive loop on the server side.
///
/// Instead of sending periodic PING messages, the server now waits for
/// incoming PING messages from the remote peer. When a PING is received,
/// the server replies with a PONG. Any error (read/write, unexpected message,
/// timeout, or connection close) causes the loop to exit gracefully.
pub async fn run_control_channel_loop<T>(
    mut auth_stream: T,
    cancel_token: CancellationToken,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        // We'll build the message manually by reading one byte at a time.
        let mut buf = Vec::with_capacity(16);

        // Read until newline is encountered or connection is closed.
        let read_result = tokio::select! {
            _ = cancel_token.cancelled() => { // In the future, this might come from a Ctrl-C signal.
                info!("Cancellation token triggered in control channel loop");
                return Ok(());
            }
            res = timeout(KEEP_ALIVE_INTERVAL + READ_TIMEOUT, async {
                let mut byte = [0; 1];
                loop {
                    let n = auth_stream.read(&mut byte).await?;
                    if n == 0 {
                        // Connection closed.
                        break;
                    }
                    buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Ok::<(), Error>(())
            }) => res,
        };

        match read_result {
            Ok(Ok(())) => {
                if buf.is_empty() {
                    // Connection closed.
                    warn!("Connection closed by remote during keepalive");
                    break;
                }

                if buf == PING_MESSAGE {
                    info!("Received PING, sending PONG");
                    if let Err(e) = auth_stream.write_all(PONG_MESSAGE).await {
                        warn!("Failed to send PONG: {}", e);
                        break;
                    }
                    if let Err(e) = auth_stream.flush().await {
                        warn!("Failed to flush PONG: {}", e);
                        break;
                    }
                } else if buf == CONNECTION_END_MESSAGE {
                    info!("Received BYE, initiating client connection shutdown");
                    cancel_token.cancel();
                    break;
                } else {
                    warn!("Unexpected message received: {:?}", buf);
                    break;
                }
            }
            Ok(Err(e)) => {
                warn!("Failed to read from stream: {:?}", e);
                break;
            }
            Err(_) => {
                warn!("Timed out waiting for PING message");
                break;
            }
        }
    }

    debug!("Control channel loop ended, cancelling token");
    cancel_token.cancel();

    Ok(())
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
        run_keepalive_client_loop(mock).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_on_wrong_response() {
        let mock = Builder::new().write(PING_MESSAGE).read(b"WRONG\n").build();
        run_keepalive_client_loop(mock).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_when_connection_closes() {
        // After the PING, the read returns EOF.
        let mock = Builder::new().write(PING_MESSAGE).build();
        run_keepalive_client_loop(mock).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_on_write_error() {
        let mock = Builder::new()
            .write_error(io::Error::other("write error"))
            .build();
        run_keepalive_client_loop(mock).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_client_stops_on_pong_timeout() {
        let start = tokio::time::Instant::now();
        run_keepalive_client_loop(NeverRead).await.unwrap();
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

        run_control_channel_loop(mock, cancel_token.clone())
            .await
            .unwrap();

        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_on_unexpected_message() {
        let mock = Builder::new().read(b"HELLO\n").build();
        let cancel_token = CancellationToken::new();

        run_control_channel_loop(mock, cancel_token.clone())
            .await
            .unwrap();

        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_when_connection_closes() {
        let mock = Builder::new()
            .read(PING_MESSAGE)
            .write(PONG_MESSAGE)
            .build();
        let cancel_token = CancellationToken::new();

        run_control_channel_loop(mock, cancel_token.clone())
            .await
            .unwrap();

        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_without_pings() {
        let cancel_token = CancellationToken::new();
        let start = tokio::time::Instant::now();

        run_control_channel_loop(NeverRead, cancel_token.clone())
            .await
            .unwrap();

        assert!(start.elapsed() >= KEEP_ALIVE_INTERVAL + READ_TIMEOUT);
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn test_server_stops_when_cancelled() {
        let cancel_token = CancellationToken::new();
        cancel_token.cancel();

        // Returns immediately, without reading anything.
        run_control_channel_loop(NeverRead, cancel_token)
            .await
            .unwrap();
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
        server.await.unwrap().unwrap();
        assert!(cancel_token.is_cancelled());
    }
}
