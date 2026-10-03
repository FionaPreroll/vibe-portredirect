// PortRedirect Client - Handle connection to QUIC/PRRS server
//
// License: GPL-3.0-only

use crate::app_data::ClientAppData;
use crate::protocol::close::CloseCode;
use crate::protocol::control::{request_listen_port, Greeting, CLIENT_SOFTWARE};
use crate::protocol::keepalive::run_keepalive_client_loop;
use crate::protocol::message::ProtocolViolation;
use crate::quic::client::ClientConfig;
use crate::PortRedirectProtocol;

use super::auth::handle_quic_auth_client_side;
use super::metrics_counters::*;
use super::tcp_forwarder::forward_tcp_to_quic_stream;

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Handles the connection to the QUIC server, authenticates and keeps it alive.
/// Called directly by run_quic_client.
///
/// Returns when the connection ends: `Ok` if the server ended the tunnel normally, otherwise an
/// error describing why it ended.
#[cfg_attr(not(coverage), tracing::instrument(skip(config, conn)))]
pub async fn handle_quic_server_connection(
    config: Arc<ClientConfig<ClientAppData>>,
    conn: quinn::Connection,
) -> Result<()> {
    // We have just connected to the QUIC server.
    SERVER_CONNECTIONS_OPENED_TOTAL.inc();

    // We need to prove we know the PSK to authenticate.
    let mut auth_stream = handle_quic_auth_client_side(Arc::clone(&config), conn.clone())
        .await
        .context("failed to authenticate against PR QUIC server")?;

    // Ask the server to accept external TCP connections on our behalf.
    let requested_port = config.app_data.remote_listen_port;
    let welcome = timeout(
        PortRedirectProtocol::CONFIGURATION_TIMEOUT,
        request_listen_port(
            &mut auth_stream,
            &Greeting::new(CLIENT_SOFTWARE, requested_port),
        ),
    )
    .await
    .context("timed out waiting for the server to confirm the listen port")?
    .with_context(|| format!("server did not listen on TCP port {}", requested_port))?;
    info!(
        "Tunnel established, server ({:?}) listens on TCP port {}",
        welcome.software(),
        welcome.listen_port
    );

    // Start the keepalive loop to maintain the QUIC connection.
    // This loop periodically sends a PING and expects a PONG response.
    // If the keepalive fails, close the connection, which ends this handler.
    let keepalive_conn = conn.clone();
    tokio::spawn(async move {
        let Err(e) = run_keepalive_client_loop(auth_stream).await;
        if keepalive_conn.close_reason().is_some() {
            return;
        }
        if e.is::<ProtocolViolation>() {
            warn!("Invalid control message, closing the connection: {:#}", e);
            CloseCode::ProtocolViolation.close(&keepalive_conn, "unexpected control message");
        } else {
            KEEPALIVE_ERRORS.inc();
            warn!("Keepalive failed, closing the connection: {:#}", e);
            CloseCode::KeepaliveFailed.close(&keepalive_conn, "keepalive failed");
        }
    });

    // Accept bidirectional QUIC streams for new forwarded connections, until the connection ends.
    let end = loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(stream) => stream,
            Err(e) => break e,
        };
        CONNECTIONS_ACCEPTED.inc();

        let stream_id = recv.id();
        debug!(
            "Opened QUIC stream for new forwarded connection, id {}",
            stream_id
        );

        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = forward_tcp_to_quic_stream(config, send, recv).await {
                TCP_FORWARDING_ERRORS.inc();
                info!(
                    "Forwarded connection (stream {}) aborted: {:#}",
                    stream_id, e
                );
            }
        });
    };

    debug!("Closed QUIC connection handler: {}", end);
    if CloseCode::of(&end) == Some(CloseCode::Ok) {
        SERVER_CONNECTIONS_GRACEFULLY_CLOSED_TOTAL.inc();
        return Ok(());
    }
    Err(anyhow::Error::new(end).context("connection to the server ended"))
}
