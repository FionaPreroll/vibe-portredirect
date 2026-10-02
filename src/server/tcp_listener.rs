// PortRedirect Server - Listener for external TCP connections
//
// License: GPL-3.0-only

use crate::bi_stream::BiStream;
use crate::server::metrics_counters::{
    QUIC_DATA_STREAM_OPENING_ERRORS, TCP_CONNECTIONS_ACCEPTED, TCP_CONNECTIONS_FAILED_ACCEPTING,
    TCP_QUIC_CONNECTIONS_CLOSED_ERROR, TCP_QUIC_CONNECTIONS_CLOSED_GRACEFUL,
};
use crate::server::tcp_forwarder::forward_tcp_to_quic_stream;
use crate::{app_data::ServerAppData, quic::server::ServerConfig};

use anyhow::Result;
use std::{sync::Arc, time::Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, warn};

#[instrument(skip(_config, quic_conn, listener, cancel_token))]
pub async fn handle_tcp_listener(
    _config: Arc<ServerConfig<ServerAppData>>,
    quic_conn: quinn::Connection,
    listener: TcpListener,
    cancel_token: CancellationToken,
) -> Result<()> {
    info!("TCP listening on {}", listener.local_addr()?);

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("Cancellation token triggered. Shutting down TCP listener");
                // TODO connections in forward_tcp_to_quic_stream should be closed as well, they are gonna stay open
                break;
            }
            accept_result = listener.accept() => {
                let (mut tcp_stream, peer_addr) = match accept_result {
                    Ok(conn) => conn,
                    Err(e) => {
                        TCP_CONNECTIONS_FAILED_ACCEPTING.inc();
                        error!("Failed to accept TCP connection: {}", e);
                        continue;
                    }
                };
                TCP_CONNECTIONS_ACCEPTED.inc();
                debug!("Accepted TCP connection from {:?}", peer_addr);

                // Open a bidirectional QUIC stream.
                let (send, recv) = match quic_conn.open_bi().await {
                    Ok(stream) => stream,
                    Err(e) => {
                        QUIC_DATA_STREAM_OPENING_ERRORS.inc();
                        error!("failed to open QUIC stream: {}", e);
                        if let Err(e) = tcp_stream.shutdown().await {
                            error!("Failed to shutdown TCP stream: {:?}", e);
                        }
                        continue;
                    }
                };

                let stream_id = recv.id(); // it's the same id for both directions
                let quic_stream = BiStream::new(recv.compat(), send.compat_write(), stream_id.to_string());
                debug!("Opened QUIC stream (id: {}) for TCP forwarding", stream_id);

                // Spawn a new task to handle forwarding between TCP and QUIC.
                tokio::spawn(async move {
                    let start_time = Instant::now();

                    if let Err(e) = forward_tcp_to_quic_stream(tcp_stream, quic_stream).await {
                        TCP_QUIC_CONNECTIONS_CLOSED_ERROR.inc();
                        warn!("TCP-to-QUIC stream terminated (id: {}): {:?}", stream_id, e);
                    } else {
                        TCP_QUIC_CONNECTIONS_CLOSED_GRACEFUL.inc();
                        debug!("TCP-to-QUIC stream (id {}) completed", stream_id);
                    }

                    debug!(
                        "Stream (id {}) terminated after {:?}",
                        stream_id,
                        start_time.elapsed()
                    );
                });
            }
        }
    }

    Ok(())
}
