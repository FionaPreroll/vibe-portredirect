// PortRedirect Client - Bridge QUIC stream to TCP
// Note the counterpart in server/tcp_forwarder.rs.
//
// License: GPL-3.0-only

use super::metrics_counters::{BYTES_TRANSMITTED_A, BYTES_TRANSMITTED_B};

use crate::app_data::ClientAppData;
use crate::forward::forward_bidirectional;
use crate::quic::client::ClientConfig;

use anyhow::{anyhow, Error, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tracing::{debug, instrument};

/// Time to wait for the destination to accept a connection.
const DESTINATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bridges a QUIC stream to a new TCP connection (client side).
#[instrument[skip(config, quic_stream)]]
pub async fn forward_tcp_to_quic_stream<QuicStreamType>(
    config: Arc<ClientConfig<ClientAppData>>,
    mut quic_stream: QuicStreamType,
) -> Result<(), Error>
where
    QuicStreamType: AsyncRead + AsyncWrite + Unpin + std::fmt::Display,
{
    // Create client-side TCP connection to the destination
    let destination = config.app_data.forward_destination;
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
