// PortRedirect Server - Listener for external TCP connections
//
// License: GPL-3.0-only

use crate::forward::reset_tcp;
use crate::limits::AddressConnectionLimit;
use crate::protocol::data_stream::send_connection_header;
use crate::server::metrics_counters::{
    QUIC_DATA_STREAM_OPENING_ERRORS, TCP_CONNECTIONS_ACCEPTED, TCP_CONNECTIONS_FAILED_ACCEPTING,
    TCP_CONNECTIONS_REFUSED, TCP_QUIC_CONNECTIONS_CLOSED_ERROR,
    TCP_QUIC_CONNECTIONS_CLOSED_GRACEFUL,
};
use crate::server::port_registry::PortLease;
use crate::server::tcp_forwarder::forward_tcp_to_quic_stream;
use crate::{app_data::ServerAppData, quic::server::ServerConfig};

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn, Instrument};

/// Time to wait for the client to accept another stream before an external connection is dropped.
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause after a failure to accept a connection, e.g. when running out of file descriptors.
const ACCEPT_ERROR_DELAY: Duration = Duration::from_secs(1);

/// Accepts external TCP connections on `listener` and forwards each through a new QUIC stream,
/// until `cancel_token` is cancelled. Then closes the listener and releases the port's `lease`.
#[cfg_attr(
    not(coverage),
    tracing::instrument(skip(config, quic_conn, listener, lease, cancel_token))
)]
pub async fn handle_tcp_listener(
    config: Arc<ServerConfig<ServerAppData>>,
    quic_conn: quinn::Connection,
    listener: TcpListener,
    lease: PortLease,
    cancel_token: CancellationToken,
) -> Result<()> {
    let result = accept_connections(&config, &quic_conn, &listener, &cancel_token).await;
    // Close the listener before releasing the port, so another connection can listen on it.
    drop(listener);
    info!("Stopped listening on TCP port {}", lease.port());
    drop(lease);
    result
}

async fn accept_connections(
    config: &ServerConfig<ServerAppData>,
    quic_conn: &quinn::Connection,
    listener: &TcpListener,
    cancel_token: &CancellationToken,
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

        // Draining the shutdown waits for the connection.
        let quic_conn = quic_conn.clone();
        config.shutdown.spawn(
            async move {
                forward_external_connection(quic_conn, tcp_stream, peer_addr, limits.idle_timeout)
                    .await;
                // The connection's slots are free again.
                drop((slot, address_slot));
            }
            .in_current_span(),
        );
    }

    Ok(())
}

/// Forwards an accepted external TCP connection through a new QUIC stream to the client.
///
/// If the connection can't be forwarded, it is reset, so the external client notices.
async fn forward_external_connection(
    quic_conn: quinn::Connection,
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    idle_timeout: Option<Duration>,
) {
    let start_time = Instant::now();

    // Open a bidirectional QUIC stream. This waits while the client doesn't accept more streams.
    let (mut send, recv) = match timeout(STREAM_OPEN_TIMEOUT, quic_conn.open_bi()).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            QUIC_DATA_STREAM_OPENING_ERRORS.inc();
            warn!("Failed to open QUIC stream for {}: {}", peer_addr, e);
            reset_tcp(&tcp_stream);
            return;
        }
        Err(_) => {
            QUIC_DATA_STREAM_OPENING_ERRORS.inc();
            warn!(
                "Client accepted no stream for {} within {:?}, resetting the connection",
                peer_addr, STREAM_OPEN_TIMEOUT
            );
            reset_tcp(&tcp_stream);
            return;
        }
    };

    let stream_id = recv.id(); // it's the same id for both directions
    debug!(
        "Opened QUIC stream (id: {}) for TCP connection from {}",
        stream_id, peer_addr
    );

    // The header tells the client about the new stream right away, even if the external client
    // waits for the destination to speak first.
    if let Err(e) = send_connection_header(&mut send, peer_addr).await {
        QUIC_DATA_STREAM_OPENING_ERRORS.inc();
        warn!("Failed to start QUIC stream for {}: {:#}", peer_addr, e);
        reset_tcp(&tcp_stream);
        return;
    }

    if let Err(e) = forward_tcp_to_quic_stream(tcp_stream, send, recv, idle_timeout).await {
        TCP_QUIC_CONNECTIONS_CLOSED_ERROR.inc();
        info!(
            "Connection from {} (stream {}) aborted: {:#}",
            peer_addr, stream_id, e
        );
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
