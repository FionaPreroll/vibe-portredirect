// PortRedirect Server - Authenticate client to server
//
// License: GPL-3.0-only

use crate::protocol::auth::{server_authenticate, session_binding, AuthenticatedClient};
use crate::quic::server::ServerConfig;
use crate::{app_data::ServerAppData, bi_stream::BiStream};

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use tracing::{debug, info};

/// The control stream of a connection, as the server sees it.
pub type ControlStream = BiStream<Compat<quinn::RecvStream>, Compat<quinn::SendStream>>;

/// Opens the control stream, which stays open for the lifetime of the connection, and
/// authenticates the client over it: verifies that the client knows the PSK of the client it
/// names and proves that we know it, too.
///
/// Called by handle_quic_client_connection, which closes the connection on failure.
#[cfg_attr(not(coverage), tracing::instrument(skip(config, conn)))]
pub async fn authenticate_quic_client(
    config: Arc<ServerConfig<ServerAppData>>,
    conn: quinn::Connection,
) -> Result<(ControlStream, AuthenticatedClient)> {
    debug!("Authenticating PR QUIC client");

    let (send, recv) = conn
        .open_bi()
        .await
        .context("failed to open the control stream")?;
    let stream_id = recv.id();
    debug!("opened control channel with stream id {}", stream_id);

    // Convert the futures-based Quinn streams into Tokio-compatible streams.
    let mut control_channel =
        BiStream::new(recv.compat(), send.compat_write(), stream_id.to_string());

    // The caller logs failures.
    let binding = session_binding(&conn)?;
    let client =
        server_authenticate(&mut control_channel, &config.app_data.clients, &binding).await?;
    let psk_count = config
        .app_data
        .clients
        .get(&client.name)
        .map_or(1, |entry| entry.psks.len());
    if psk_count > 1 {
        info!(
            "Authenticated client {:?} with PSK {} of {}",
            client.name.as_str(),
            client.psk_index + 1,
            psk_count
        );
    } else {
        info!("Authenticated client {:?}", client.name.as_str());
    }

    Ok((control_channel, client))
}
