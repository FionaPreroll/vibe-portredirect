// PortRedirect Protocol Module - Control Channel Implementation
// License: GPL-3.0-only

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::bi_stream::BiStream;

/// Header of the client's request asking the server to listen on a TCP port.
const LISTEN_PORT_REQUEST_HEADER: &[u8; 10] = b"LISTENPORT";
/// Header of the server's confirmation that the TCP listener is bound.
const LISTENING_RESPONSE_HEADER: &[u8; 9] = b"LISTENING";

// Structure to hold the client's requested configuration.
pub struct RequestedClientConfiguration {
    pub port: u16,
}

/// Receives the client's desired configuration over the control channel.
/// The client must send a control message in the form:
///
/// ```text
/// LISTENPORTxx
/// ```
///
/// where:
/// - `"LISTENPORT"` is a literal header (10 ASCII bytes),
/// - `xx` is a 2-byte big‑endian encoded u16 port number.
///
/// The caller is responsible for checking that the requested port is allowed by the server's
/// configuration, and for confirming it with [`confirm_client_configuration`].
pub async fn configure_quic_client<R, W>(
    mut control_channel: BiStream<R, W>,
) -> Result<(RequestedClientConfiguration, BiStream<R, W>)>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // 1. Read the fixed header ("LISTENPORT").
    let mut header_buf = [0u8; LISTEN_PORT_REQUEST_HEADER.len()];
    control_channel
        .read
        .read_exact(&mut header_buf)
        .await
        .context("failed to read control message header from client")?;

    if &header_buf != LISTEN_PORT_REQUEST_HEADER {
        return Err(anyhow!(
            "invalid control message header: expected 'LISTENPORT', got {:?}",
            String::from_utf8_lossy(&header_buf)
        ));
    }

    // 2. Read the port bytes.
    let mut port_buf = [0u8; 2];
    control_channel
        .read
        .read_exact(&mut port_buf)
        .await
        .context("failed to read port bytes from client")?;
    let port = u16::from_be_bytes(port_buf);

    Ok((RequestedClientConfiguration { port }, control_channel))
}

/// Confirms to the client that the server is now listening on `bound_port` (server side).
///
/// The confirmation is sent as:
///
/// ```text
/// LISTENINGxx
/// ```
///
/// where `"LISTENING"` is a literal header (9 ASCII bytes) and `xx` is the 2-byte big-endian
/// encoded port the TCP listener is bound to.
pub async fn confirm_client_configuration<R, W>(
    control_channel: &mut BiStream<R, W>,
    bound_port: u16,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut message = Vec::with_capacity(LISTENING_RESPONSE_HEADER.len() + 2);
    message.extend_from_slice(LISTENING_RESPONSE_HEADER);
    message.extend_from_slice(&bound_port.to_be_bytes());

    control_channel
        .write
        .write_all(&message)
        .await
        .context("failed to send configuration confirmation to client")?;
    control_channel
        .write
        .flush()
        .await
        .context("failed to flush configuration confirmation to client")?;
    Ok(())
}

/// Asks the server to listen on TCP port `port` and waits for its confirmation (client side).
///
/// Counterpart of [`configure_quic_client`] and [`confirm_client_configuration`].
/// Returns the port the server's TCP listener is bound to.
pub async fn request_listen_port<R, W>(
    control_channel: &mut BiStream<R, W>,
    port: u16,
) -> Result<u16>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // 1. Send the request.
    let mut request = Vec::with_capacity(LISTEN_PORT_REQUEST_HEADER.len() + 2);
    request.extend_from_slice(LISTEN_PORT_REQUEST_HEADER);
    request.extend_from_slice(&port.to_be_bytes());

    control_channel
        .write
        .write_all(&request)
        .await
        .context("failed to send listen port request to server")?;
    control_channel
        .write
        .flush()
        .await
        .context("failed to flush listen port request to server")?;

    // 2. Wait for the confirmation. The server closes the connection instead if it refuses.
    let mut header_buf = [0u8; LISTENING_RESPONSE_HEADER.len()];
    control_channel
        .read
        .read_exact(&mut header_buf)
        .await
        .context("server did not confirm the listen port request")?;

    if &header_buf != LISTENING_RESPONSE_HEADER {
        return Err(anyhow!(
            "invalid control message header: expected 'LISTENING', got {:?}",
            String::from_utf8_lossy(&header_buf)
        ));
    }

    let mut port_buf = [0u8; 2];
    control_channel
        .read
        .read_exact(&mut port_buf)
        .await
        .context("failed to read confirmed port from server")?;

    Ok(u16::from_be_bytes(port_buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, split};

    #[tokio::test]
    async fn test_listen_port_roundtrip() -> Result<()> {
        let (client_side, server_side) = duplex(64);

        let server = tokio::spawn(async move {
            let (read, write) = split(server_side);
            let control_channel = BiStream::new(read, write, "server".to_string());
            let (requested, mut control_channel) = configure_quic_client(control_channel).await?;
            confirm_client_configuration(&mut control_channel, requested.port + 1).await?;
            Ok::<u16, anyhow::Error>(requested.port)
        });

        let (read, write) = split(client_side);
        let mut control_channel = BiStream::new(read, write, "client".to_string());
        let bound_port = request_listen_port(&mut control_channel, 4242).await?;

        assert_eq!(server.await??, 4242);
        assert_eq!(bound_port, 4243);
        Ok(())
    }

    #[tokio::test]
    async fn test_configure_rejects_invalid_header() {
        let (mut client_side, server_side) = duplex(64);
        client_side.write_all(b"LISTENPOXT\x00\x50").await.unwrap();

        let (read, write) = split(server_side);
        let result = configure_quic_client(BiStream::new(read, write, "server".into())).await;

        let err = result.err().expect("invalid header must be rejected");
        assert!(err.to_string().contains("invalid control message header"));
    }

    #[tokio::test]
    async fn test_configure_rejects_truncated_request() {
        let (mut client_side, server_side) = duplex(64);
        client_side.write_all(b"LISTENPORT\x00").await.unwrap();
        drop(client_side);

        let (read, write) = split(server_side);
        let result = configure_quic_client(BiStream::new(read, write, "server".into())).await;

        assert!(result.is_err(), "truncated request must be rejected");
    }

    #[tokio::test]
    async fn test_request_rejects_invalid_confirmation() {
        let (client_side, mut server_side) = duplex(64);
        server_side.write_all(b"LISTENINX\x00\x50").await.unwrap();

        let (read, write) = split(client_side);
        let mut control_channel = BiStream::new(read, write, "client".into());
        let result = request_listen_port(&mut control_channel, 80).await;

        let err = result.expect_err("invalid confirmation must be rejected");
        assert!(err.to_string().contains("invalid control message header"));
    }

    #[tokio::test]
    async fn test_request_fails_when_server_closes() {
        let (client_side, server_side) = duplex(64);
        drop(server_side);

        let (read, write) = split(client_side);
        let mut control_channel = BiStream::new(read, write, "client".into());
        let result = request_listen_port(&mut control_channel, 80).await;

        assert!(result.is_err(), "missing confirmation must be an error");
    }
}
