// PortRedirect Server - Bridge TCP to QUIC stream
// Note the counterpart in client/tcp_forwarder.rs.
//
// License: GPL-3.0-only

use super::metrics_counters::{BYTES_TRANSMITTED_A, BYTES_TRANSMITTED_B};

use crate::forward::forward_tcp_and_quic;

use anyhow::Result;
use std::time::Duration;
use tracing::debug;

/// Forwards an incoming TCP connection to a QUIC stream (server side), and passes on aborts, see
/// [`forward_tcp_and_quic`].
///
/// Forwarding ends when no data was transferred for `idle_timeout`, if given.
#[cfg_attr(not(coverage), tracing::instrument(skip(tcp_stream, send, recv)))]
pub async fn forward_tcp_to_quic_stream(
    tcp_stream: tokio::net::TcpStream,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    idle_timeout: Option<Duration>,
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
