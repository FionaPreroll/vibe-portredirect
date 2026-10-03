// PortRedirect Server - Bridge TCP to QUIC stream
// Note the counterpart in client/tcp_forwarder.rs.
//
// License: GPL-3.0-only

use super::metrics_counters::{BYTES_TRANSMITTED_A, BYTES_TRANSMITTED_B};

use crate::forward::forward_bidirectional;

use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

/// Forwards an incoming TCP connection to a QUIC stream (server side).
///
/// Forwarding ends when no data was transferred for `idle_timeout`, if given.
#[cfg_attr(not(coverage), tracing::instrument(skip(tcp_stream, quic_stream)))]
pub async fn forward_tcp_to_quic_stream<QuicStreamType>(
    mut tcp_stream: tokio::net::TcpStream,
    mut quic_stream: QuicStreamType,
    idle_timeout: Option<Duration>,
) -> Result<()>
where
    QuicStreamType: AsyncRead + AsyncWrite + Unpin + std::fmt::Display,
{
    // On the server side, the TCP stream is already open, as it was externally initiated.

    // Forward TCP connection to client through QUIC stream.
    let stream_name = format!("Server-A:TCP-B:QUIC({})", quic_stream);
    debug!(
        "Starting TCP<->QUIC stream handler, stream id {}",
        stream_name.clone()
    );

    forward_bidirectional(
        &mut tcp_stream,  // A
        &mut quic_stream, // B
        stream_name.clone(),
        // Force dereferencing here because the counter is a LazyStatic.
        &*BYTES_TRANSMITTED_A,
        &*BYTES_TRANSMITTED_B,
        idle_timeout,
    )
    .await?;

    debug!(
        "Closed TCP<->QUIC stream handler, stream id {}",
        stream_name
    );
    Ok(())
}
