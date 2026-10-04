// PortRedirect Client - Bridge QUIC stream to TCP
// Note the counterpart in server/tcp_forwarder.rs.
//
// License: GPL-3.0-only

use super::metrics::METRICS;

use crate::app_data::ClientAppData;
use crate::forward::{abort_quic_stream, forward_tcp_and_quic};
use crate::host_port::HostPort;
use crate::logging::CONNECTION_LOG;
use crate::metrics::{CounterWithTotal, MetricsCounter};
use crate::protocol::data_stream::{receive_connection_header, StreamErrorCode};
use crate::quic::client::ClientConfig;

use anyhow::{anyhow, Error, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{timeout, Instant};
use tracing::{debug, info};

/// Time to look up the destination and wait for it to accept a connection.
const DESTINATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time to wait for the header of a new data stream, which the server sends right away.
const CONNECTION_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Bridges a QUIC stream to a new TCP connection to the destination (client side), and passes
/// on aborts, see [`forward_tcp_and_quic`].
///
/// If the destination is unreachable, resets the stream with
/// [`StreamErrorCode::ConnectFailed`], so the server resets the external connection.
#[cfg_attr(not(coverage), tracing::instrument(skip(config, send, recv)))]
pub async fn forward_tcp_to_quic_stream(
    config: Arc<ClientConfig<ClientAppData>>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), Error> {
    // The server names the external client first.
    let peer = match timeout(
        CONNECTION_HEADER_TIMEOUT,
        receive_connection_header(&mut recv),
    )
    .await
    {
        Ok(Ok(peer)) => peer,
        Ok(Err(e)) => {
            abort_quic_stream(&mut send, &mut recv, StreamErrorCode::Aborted);
            return Err(e);
        }
        Err(_) => {
            abort_quic_stream(&mut send, &mut recv, StreamErrorCode::Aborted);
            return Err(anyhow!(
                "no connection header within {:?}",
                CONNECTION_HEADER_TIMEOUT
            ));
        }
    };

    // With --log-connections, each connection is logged, see CONNECTION_LOG.
    let destination = &config.app_data.forward_destination;
    debug!("Forwarding connection from {} to {}", peer, destination);
    info!(
        target: CONNECTION_LOG,
        external_client = %peer,
        destination = %destination,
        "Connection opened"
    );
    let start = Instant::now();
    let to_destination = CounterWithTotal::new(&METRICS.bytes_to_destination);
    let from_destination = CounterWithTotal::new(&METRICS.bytes_from_destination);
    let result =
        forward_to_destination(destination, send, recv, &to_destination, &from_destination).await;
    let duration_ms = start.elapsed().as_millis() as u64;
    let (bytes_to_destination, bytes_from_destination) =
        (to_destination.total(), from_destination.total());
    match &result {
        Ok(()) => info!(
            target: CONNECTION_LOG,
            external_client = %peer,
            destination = %destination,
            duration_ms,
            bytes_to_destination,
            bytes_from_destination,
            "Connection closed"
        ),
        Err(e) => {
            let error = format!("{:#}", e);
            info!(
                target: CONNECTION_LOG,
                external_client = %peer,
                destination = %destination,
                duration_ms,
                bytes_to_destination,
                bytes_from_destination,
                error = %error,
                "Connection aborted"
            )
        }
    }
    result
}

/// Connects to `destination` and forwards the connection between it and the QUIC stream,
/// counting the bytes it forwards in each direction.
async fn forward_to_destination(
    destination: &HostPort,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    to_destination: &impl MetricsCounter,
    from_destination: &impl MetricsCounter,
) -> Result<()> {
    // A name is looked up each time, and each of its addresses is tried in turn, e.g. IPv6 and
    // IPv4 for localhost.
    let connected = timeout(
        DESTINATION_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(destination.as_tuple()),
    )
    .await;
    let tcp_stream = match connected {
        Ok(Ok(tcp_stream)) => tcp_stream,
        Ok(Err(e)) => {
            METRICS.destination_connect_failures.inc();
            abort_quic_stream(&mut send, &mut recv, StreamErrorCode::ConnectFailed);
            return Err(anyhow!(
                "failed to connect to destination {}: {}",
                destination,
                e
            ));
        }
        Err(_) => {
            METRICS.destination_connect_failures.inc();
            abort_quic_stream(&mut send, &mut recv, StreamErrorCode::ConnectFailed);
            return Err(anyhow!(
                "connecting to destination {} timed out after {:?}",
                destination,
                DESTINATION_CONNECT_TIMEOUT
            ));
        }
    };

    // Run QUIC stream handler that forwards TCP connection to server
    let stream_name = format!("Client-A:TCP-B:QUIC({})", recv.id());
    debug!(
        "Starting TCP<->QUIC stream handler, stream id {}",
        stream_name
    );

    forward_tcp_and_quic(
        tcp_stream,
        send,
        recv,
        &stream_name,
        from_destination,
        to_destination,
        // The server closes idle connections.
        None,
    )
    .await?;

    debug!(
        "Closed TCP<->QUIC stream handler, stream id {}",
        stream_name
    );
    Ok(())
}
