// PortRedirect Server - Listener for external TCP connections
//
// License: GPL-3.0-only

use crate::forward::reset_tcp;
use crate::host_port::HostPort;
use crate::limits::{AddressConnectionLimit, AddressRateLimit};
use crate::metrics::Active;
use crate::net::{canonical, receive_ipv4_on_any_ipv6};
use crate::protocol::data_stream::send_connection_header;
use crate::server::metrics::ClientMetrics;
use crate::server::port_registry::PortLease;
use crate::server::tcp_forwarder::forward_tcp_to_quic_stream;
use crate::{app_data::ServerAppData, quic::server::ServerConfig};

use anyhow::Result;
use socket2::SockRef;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn, Instrument};

/// Time to wait for the client to accept another stream before an external connection is dropped.
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause after a failure to accept a connection, e.g. when running out of file descriptors.
const ACCEPT_ERROR_DELAY: Duration = Duration::from_secs(1);

/// Listens for external TCP connections on `address`, on the first of a name's addresses that
/// works. On `::`, it accepts IPv4 connections, too.
pub async fn bind_tcp_listener(address: &HostPort) -> io::Result<TcpListener> {
    let mut error = None;
    for address in address.lookup().await? {
        match listen(address) {
            Ok(listener) => return Ok(listener),
            Err(e) => error = Some(e),
        }
    }
    Err(error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address")))
}

/// Listens on `address`, like `TcpListener::bind`, but on `::` for IPv4 connections, too, see
/// [`receive_ipv4_on_any_ipv6`].
fn listen(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = match address {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    receive_ipv4_on_any_ipv6(SockRef::from(&socket), address);
    // As TcpListener::bind does, so the port can be bound again right after a listener ended,
    // while its connections linger. On Windows, this would let others take the port, though.
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(1024)
}

/// Accepts external TCP connections on `listener` and forwards each through a new QUIC stream,
/// until `cancel_token` is cancelled. Then closes the listener and releases the port's `lease`.
/// Counts in the client's `metrics`.
#[cfg_attr(
    not(coverage),
    tracing::instrument(skip(config, quic_conn, listener, lease, metrics, cancel_token))
)]
pub async fn handle_tcp_listener(
    config: Arc<ServerConfig<ServerAppData>>,
    quic_conn: quinn::Connection,
    listener: TcpListener,
    lease: PortLease,
    metrics: ClientMetrics,
    cancel_token: CancellationToken,
) -> Result<()> {
    let result = accept_connections(&config, &quic_conn, &listener, &metrics, &cancel_token).await;
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
    metrics: &ClientMetrics,
    cancel_token: &CancellationToken,
) -> Result<()> {
    let limits = config.app_data.forwarding_limits;
    info!(
        "TCP listening on {} (at most {} connections, {} per address, {} new ones per second and address after {} at once)",
        listener.local_addr()?,
        limits.max_connections,
        limits.max_connections_per_ip,
        limits.max_connection_rate_per_ip,
        limits.max_connection_burst_per_ip
    );

    let connection_slots = Arc::new(Semaphore::new(limits.max_connections));
    let address_limit = AddressConnectionLimit::new(limits.max_connections_per_ip);
    let rate_limit = AddressRateLimit::new(
        limits.max_connection_rate_per_ip,
        limits.max_connection_burst_per_ip,
    );

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
            // A listener on :: sees IPv4 clients at IPv4-mapped IPv6 addresses.
            Ok((tcp_stream, peer_addr)) => (tcp_stream, canonical(peer_addr)),
            Err(e) => {
                metrics.accept_errors.inc();
                warn!("Failed to accept TCP connection: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
                continue;
            }
        };
        // Limit the connections per address, so a single host can't use up all slots.
        let Some(address_slot) = address_limit.try_acquire(peer_addr.ip()) else {
            metrics.forwarded_connections_refused.address_limit.inc();
            debug!(
                "Closing TCP connection from {}: too many connections from this address",
                peer_addr
            );
            continue;
        };
        // Limit how fast a single host can open forwarded connections, as each makes the client
        // connect to the destination.
        if !rate_limit.try_take(peer_addr.ip()) {
            metrics.forwarded_connections_refused.rate_limit.inc();
            debug!(
                "Closing TCP connection from {}: too many new connections from this address",
                peer_addr
            );
            continue;
        }
        debug!("Accepted TCP connection from {}", peer_addr);
        metrics.forwarded_connections.inc();

        // Draining the shutdown waits for the connection.
        let (quic_conn, metrics) = (quic_conn.clone(), metrics.clone());
        config.shutdown.spawn(
            async move {
                let _active = Active::new(&metrics.forwarded_connections_active);
                forward_external_connection(
                    quic_conn,
                    tcp_stream,
                    peer_addr,
                    limits.idle_timeout,
                    &metrics,
                )
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
    metrics: &ClientMetrics,
) {
    let start_time = Instant::now();

    // Open a bidirectional QUIC stream. This waits while the client doesn't accept more streams.
    let (mut send, recv) = match timeout(STREAM_OPEN_TIMEOUT, quic_conn.open_bi()).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            metrics.forwarded_connections_failed.inc();
            warn!("Failed to open QUIC stream for {}: {}", peer_addr, e);
            reset_tcp(&tcp_stream);
            return;
        }
        Err(_) => {
            metrics.forwarded_connections_failed.inc();
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
        metrics.forwarded_connections_failed.inc();
        warn!("Failed to start QUIC stream for {}: {:#}", peer_addr, e);
        reset_tcp(&tcp_stream);
        return;
    }

    if let Err(e) = forward_tcp_to_quic_stream(tcp_stream, send, recv, idle_timeout, metrics).await
    {
        metrics.forwarded_connections_aborted.inc();
        info!(
            "Connection from {} (stream {}) aborted: {:#}",
            peer_addr, stream_id, e
        );
    } else {
        debug!("TCP-to-QUIC stream (id {}) completed", stream_id);
    }

    debug!(
        "Stream (id {}) terminated after {:?}",
        stream_id,
        start_time.elapsed()
    );
}
