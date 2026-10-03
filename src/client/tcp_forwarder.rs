// PortRedirect Client - Bridge QUIC stream to TCP
// Note the counterpart in server/tcp_forwarder.rs.
//
// License: GPL-3.0-only

use super::metrics_counters::{BYTES_TRANSMITTED_A, BYTES_TRANSMITTED_B};

use crate::app_data::ClientAppData;
use crate::forward::forward_bidirectional;
use crate::protocol::data_stream::receive_connection_header;
use crate::quic::client::ClientConfig;

use anyhow::{anyhow, Error, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tracing::debug;

/// Time to wait for the destination to accept a connection.
const DESTINATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time to wait for the header of a new data stream, which the server sends right away.
const CONNECTION_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Bridges a QUIC stream to a new TCP connection (client side).
#[cfg_attr(not(coverage), tracing::instrument(skip(config, quic_stream)))]
pub async fn forward_tcp_to_quic_stream<QuicStreamType>(
    config: Arc<ClientConfig<ClientAppData>>,
    mut quic_stream: QuicStreamType,
) -> Result<(), Error>
where
    QuicStreamType: AsyncRead + AsyncWrite + Unpin + std::fmt::Display,
{
    // The server names the external client first.
    let peer = timeout(
        CONNECTION_HEADER_TIMEOUT,
        receive_connection_header(&mut quic_stream),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "no connection header within {:?}",
            CONNECTION_HEADER_TIMEOUT
        )
    })??;

    // Create client-side TCP connection to the destination
    let destination = config.app_data.forward_destination;
    debug!("Forwarding connection from {} to {}", peer, destination);
    let mut tcp_stream = timeout(
        DESTINATION_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(destination),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "connecting to destination {} timed out after {:?}",
            destination,
            DESTINATION_CONNECT_TIMEOUT
        )
    })?
    .map_err(|e| anyhow!("failed to connect to destination {}: {}", destination, e))?;

    // Run QUIC stream handler that forwards TCP connection to server
    let stream_name = format!("Client-A:TCP-B:QUIC({})", quic_stream);
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
