// PortRedirect Client - PSK authentication
//
// License: GPL-3.0-only

use crate::protocol::auth::{client_authenticate, session_binding, AuthenticationRejected};
use crate::protocol::close::CloseCode;
use crate::quic::client::ClientConfig;
use crate::{app_data::ClientAppData, bi_stream::BiStream};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::{debug, info};

/// Accepts the control stream, which the server opens first, and authenticates over it: names
/// the client, proves that we know the PSK and verifies that the server knows it, too.
///
/// Closes the connection if the server fails to prove its knowledge of the PSK.
#[cfg_attr(not(coverage), tracing::instrument(skip(config, conn)))]
pub async fn handle_quic_auth_client_side(
    config: Arc<ClientConfig<ClientAppData>>,
    conn: quinn::Connection,
) -> Result<BiStream<Compat<quinn::RecvStream>, Compat<quinn::SendStream>>> {
    debug!("Accepting server-initiated QUIC stream.");
    let (send, recv) = conn
        .accept_bi()
        .await
        .context("failed to accept the control stream")?;
    let stream_id = recv.id();
    let mut control_stream =
        BiStream::new(recv.compat(), send.compat_write(), stream_id.to_string());
    debug!("opened control stream with id {}", stream_id);

    // On failure, the caller adds the context and logs the error.
    let binding = session_binding(&conn)?;
    if let Err(e) = client_authenticate(
        &mut control_stream,
        &config.app_data.client_name,
        &config.app_data.connection_auth_psk,
        &binding,
    )
    .await
    {
        if e.is::<AuthenticationRejected>() {
            CloseCode::AuthenticationFailed.close(&conn, "authentication failed");
        }
        return Err(e);
    }
    info!("Authentication successful");

    Ok(control_stream)
}
