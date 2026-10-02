// PortRedirect Client - PSK authentication
//
// License: GPL-3.0-only

use crate::protocol::auth::client_authenticate;
use crate::quic::client::ClientConfig;
use crate::{app_data::ClientAppData, bi_stream::BiStream};
use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::{debug, info, instrument, warn};

// Handles our custom authentication stream.
#[instrument[skip(config, conn)]]
pub async fn handle_quic_auth_client_side(
    config: Arc<ClientConfig<ClientAppData>>,
    conn: quinn::Connection,
) -> Result<BiStream<Compat<quinn::RecvStream>, Compat<quinn::SendStream>>> {
    // Accept the first QUIC stream, which is for authenticating us to the server.
    debug!("Accepting server-initiated QUIC stream.");

    // Client auth loop. Runs until server is happy.
    if let Ok((send, recv)) = conn.accept_bi().await {
        let stream_id = recv.id();
        let mut bi_stream =
            BiStream::new(recv.compat(), send.compat_write(), stream_id.to_string());
        debug!("opened bidi channel for AUTH with stream {}", stream_id);

        match client_authenticate(&mut bi_stream, config.app_data.connection_auth_psk.clone()).await
        {
            Ok(()) => {
                info!("Authentication successful");
            }
            Err(e) => {
                warn!("Authentication failed: {}", e);
                return Err(anyhow!("failed to authenticate against PR QUIC server"));
            }
        }

        Ok(bi_stream)
    } else {
        Err(anyhow!("failed to accept bidi AUTH connection"))
    }
}
