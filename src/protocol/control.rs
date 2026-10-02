// PortRedirect Protocol Module - Control Channel Implementation
// License: GPL-3.0-only

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;

use crate::bi_stream::BiStream;

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
/// The function checks that the requested port is allowed by the server's configuration.
pub async fn configure_quic_client<R, W>(
    mut control_channel: BiStream<R, W>,
) -> Result<(RequestedClientConfiguration, BiStream<R, W>)>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // 1. Read the fixed header ("LISTENPORT").
    let mut header_buf = [0u8; 10];
    control_channel
        .read
        .read_exact(&mut header_buf)
        .await
        .context("failed to read control message header from client")?;

    let header =
        std::str::from_utf8(&header_buf).context("control message header is not valid UTF-8")?;

    if header != "LISTENPORT" {
        return Err(anyhow::anyhow!(
            "invalid control message header: expected 'LISTENPORT', got '{}'",
            header
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
