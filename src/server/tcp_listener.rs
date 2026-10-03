// PortRedirect Server - Listener for external TCP connections
//
// License: GPL-3.0-only

use crate::bi_stream::BiStream;
use crate::limits::AddressConnectionLimit;
use crate::server::metrics_counters::{
    QUIC_DATA_STREAM_OPENING_ERRORS, TCP_CONNECTIONS_ACCEPTED, TCP_CONNECTIONS_FAILED_ACCEPTING,
    TCP_CONNECTIONS_REFUSED, TCP_QUIC_CONNECTIONS_CLOSED_ERROR,
    TCP_QUIC_CONNECTIONS_CLOSED_GRACEFUL,
};
use crate::server::tcp_forwarder::forward_tcp_to_quic_stream;
use crate::{app_data::ServerAppData, quic::server::ServerConfig};

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};

/// Time to wait for the client to accept another stream before an external connection is dropped.
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause after a failure to accept a connection, e.g. when running out of file descriptors.
const ACCEPT_ERROR_DELAY: Duration = Duration::from_secs(1);

#[instrument(skip(config, quic_conn, listener, cancel_token))]
pub async fn handle_tcp_listener(
    config: Arc<ServerConfig<ServerAppData>>,
    quic_conn: quinn::Connection,
    listener: TcpListener,
    cancel_token: CancellationToken,
) -> Result<()> {
    let limits = config.app_data.forwarding_limits;
    info!(
        "TCP listening on {} (at most {} connections, {} per address)",
        listener.local_addr()?,
        limits.max_connections,
        limits.max_connections_per_ip
    );

    let connection_slots = Arc::new(Semaphore::new(limits.max_connections));
    let address_limit = AddressConnectionLimit::new(limits.max_connections_per_ip);

    loop {
        // Wait for a free slot first: while all slots are in use, new connections wait in the
        // listen backlog instead of using up resources.
        let slot = tokio::select! {
            _ = cancel_token.cancelled() => break,
            slot = Arc::clone(&connection_slots).acquire_owned() => {
                slot.expect("the connection semaphore is never closed")
            }
        };

        let accept_result = tokio::select! {
            _ = cancel_token.cancelled() => break,
            accept_result = listener.accept() => accept_result,
        };
        let (tcp_stream, peer_addr) = match accept_result {
            Ok(connection) => connection,
            Err(e) => {
                TCP_CONNECTIONS_FAILED_ACCEPTING.inc();
                warn!("Failed to accept TCP connection: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
                continue;
            }
        };
        TCP_CONNECTIONS_ACCEPTED.inc();

        // Limit the connections per address, so a single host can't use up all slots.
        let Some(address_slot) = address_limit.try_acquire(peer_addr.ip()) else {
            TCP_CONNECTIONS_REFUSED.inc();
            debug!(
                "Closing TCP connection from {}: too many connections from this address",
                peer_addr
            );
            continue;
        };
        debug!("Accepted TCP connection from {}", peer_addr);

        let quic_conn = quic_conn.clone();
        tokio::spawn(async move {
            forward_external_connection(quic_conn, tcp_stream, peer_addr, limits.idle_timeout)
                .await;
            // The connection's slots are free again.
            drop((slot, address_slot));
        });
    }

    info!("Shutting down TCP listener");
    Ok(())
}

/// Forwards an accepted external TCP connection through a new QUIC stream to the client.
async fn forward_external_connection(
    quic_conn: quinn::Connection,
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    idle_timeout: Option<Duration>,
) {
    let start_time = Instant::now();

    // Open a bidirectional QUIC stream. This waits while the client doesn't accept more streams.
    let (send, recv) = match timeout(STREAM_OPEN_TIMEOUT, quic_conn.open_bi()).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            QUIC_DATA_STREAM_OPENING_ERRORS.inc();
            warn!("Failed to open QUIC stream for {}: {}", peer_addr, e);
            return;
        }
        Err(_) => {
            QUIC_DATA_STREAM_OPENING_ERRORS.inc();
            warn!(
                "Client accepted no stream for {} within {:?}, closing the connection",
                peer_addr, STREAM_OPEN_TIMEOUT
            );
            return;
        }
    };

    let stream_id = recv.id(); // it's the same id for both directions
    let quic_stream = BiStream::new(recv.compat(), send.compat_write(), stream_id.to_string());
    debug!(
        "Opened QUIC stream (id: {}) for TCP connection from {}",
        stream_id, peer_addr
    );

    if let Err(e) = forward_tcp_to_quic_stream(tcp_stream, quic_stream, idle_timeout).await {
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
}
