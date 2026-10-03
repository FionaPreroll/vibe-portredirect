// PortRedirect Server - Bridge TCP to QUIC stream
// Note the counterpart in client/tcp_forwarder.rs.
//
// License: GPL-3.0-only

use super::metrics::ClientMetrics;

use crate::forward::forward_tcp_and_quic;

use anyhow::Result;
use std::time::Duration;
use tracing::debug;

/// Forwards an incoming TCP connection to a QUIC stream (server side), and passes on aborts, see
/// [`forward_tcp_and_quic`].
///
/// Forwarding ends when no data was transferred for `idle_timeout`, if given.
/// Counts the bytes in the client's `metrics`.
#[cfg_attr(
    not(coverage),
    tracing::instrument(skip(tcp_stream, send, recv, metrics))
)]
pub async fn forward_tcp_to_quic_stream(
    tcp_stream: tokio::net::TcpStream,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    idle_timeout: Option<Duration>,
    metrics: &ClientMetrics,
) -> Result<()> {
    // On the server side, the TCP stream is already open, as it was externally initiated.
    let stream_name = format!("Server-A:TCP-B:QUIC({})", recv.id());
    debug!(
        "Starting TCP<->QUIC stream handler, stream id {}",
        stream_name
    );

    forward_tcp_and_quic(
        tcp_stream,
        send,
        recv,
        &stream_name,
        &metrics.bytes_from_external,
        &metrics.bytes_to_external,
        idle_timeout,
    )
    .await?;

    debug!(
        "Closed TCP<->QUIC stream handler, stream id {}",
        stream_name
    );
    Ok(())
}
