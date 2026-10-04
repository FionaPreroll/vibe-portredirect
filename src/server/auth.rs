// PortRedirect Server - Authenticate client to server
//
// License: GPL-3.0-only

use crate::protocol::auth::{server_authenticate, session_binding, AuthenticatedClient};
use crate::protocol::close::CloseCode;
use crate::quic::server::{raise_receive_window, ServerConfig};
use crate::PortRedirectProtocol;
use crate::{app_data::ServerAppData, bi_stream::BiStream};

use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use tokio::time::timeout;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use tracing::{debug, info};

/// The control stream of a connection, as the server sees it.
pub type ControlStream = BiStream<Compat<quinn::RecvStream>, Compat<quinn::SendStream>>;

/// Opens the control stream, which stays open for the lifetime of the connection, and
/// authenticates the client over it: verifies that the client knows the PSK of the client it
/// names and proves that we know it, too.
///
/// If that fails or takes too long, closes the connection with the reason and fails. The caller
/// logs the error.
#[cfg_attr(not(coverage), tracing::instrument(skip(config, conn)))]
pub async fn authenticate_quic_client(
    config: Arc<ServerConfig<ServerAppData>>,
    conn: quinn::Connection,
) -> Result<(ControlStream, AuthenticatedClient)> {
    debug!("Authenticating PR QUIC client");

    // The control stream must outlive the closing of the connection: dropping a stream ends it,
    // and the client could read that end before the reason, e.g. a rejected PSK, and take it for
    // a temporary failure. So it is kept here, outside the timed authentication.
    let mut control_stream = None;
    let authenticated = timeout(
        PortRedirectProtocol::AUTHENTICATION_TIMEOUT,
        authenticate(&config, &conn, &mut control_stream),
    )
    .await;
    let client = match authenticated {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => {
            CloseCode::AuthenticationFailed.close(&conn, "authentication failed");
            return Err(e);
        }
        Err(_) => {
            CloseCode::AuthenticationTimeout.close(&conn, "authentication timed out");
            return Err(anyhow!("authentication timed out"));
        }
    };
    let control_stream = control_stream.context("authenticated without a control stream")?;
    // Until now, the client could only send a little.
    raise_receive_window(&conn);
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

    Ok((control_stream, client))
}

/// Opens the control stream into `control_stream` and authenticates the client over it.
async fn authenticate(
    config: &ServerConfig<ServerAppData>,
    conn: &quinn::Connection,
    control_stream: &mut Option<ControlStream>,
) -> Result<AuthenticatedClient> {
    let (send, recv) = conn
        .open_bi()
        .await
        .context("failed to open the control stream")?;
    let stream_id = recv.id();
    debug!("opened control channel with stream id {}", stream_id);

    // Convert the futures-based Quinn streams into Tokio-compatible streams.
    let control_stream = control_stream.insert(BiStream::new(
        recv.compat(),
        send.compat_write(),
        stream_id.to_string(),
    ));
    let binding = session_binding(conn)?;
    server_authenticate(control_stream, &config.app_data.clients, &binding).await
}
