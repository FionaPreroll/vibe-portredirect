// PortRedirect Client - Bridge QUIC stream to TCP
// Note the counterpart in server/tcp_forwarder.rs.
//
// License: GPL-3.0-only

use super::metrics::METRICS;

use crate::app_data::ClientAppData;
use crate::forward::{abort_quic_stream, forward_tcp_and_quic};
use crate::protocol::data_stream::{receive_connection_header, StreamErrorCode};
use crate::quic::client::ClientConfig;

use anyhow::{anyhow, Error, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::debug;

/// Time to wait for the destination to accept a connection.
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

    // Create client-side TCP connection to the destination
    let destination = config.app_data.forward_destination;
    debug!("Forwarding connection from {} to {}", peer, destination);
    let connected = timeout(
        DESTINATION_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(destination),
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
        &METRICS.bytes_from_destination,
        &METRICS.bytes_to_destination,
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
