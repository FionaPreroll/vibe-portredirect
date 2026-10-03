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
use super::metrics::METRICS;
use super::tcp_forwarder::forward_tcp_to_quic_stream;

use crate::bi_stream::BiStream;
use crate::metrics::Active;

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::time::timeout;
use tokio_util::compat::Compat;
use tracing::{debug, info, warn};

/// Handles the connection to the QUIC server, authenticates and keeps it alive.
/// Called directly by run_quic_client.
///
/// When `config.shutdown` drains, the keepalive sends DRAIN, so the server stops listening for
/// new connections, the running forwarded connections may finish within the shutdown timeout,
/// and then the connection is closed.
///
/// Returns when the connection ends: `Ok` if the server ended the tunnel normally or the client
/// shut down, otherwise an error describing why it ended.
#[cfg_attr(not(coverage), tracing::instrument(skip(config, conn)))]
pub async fn handle_quic_server_connection(
    config: Arc<ClientConfig<ClientAppData>>,
    conn: quinn::Connection,
) -> Result<()> {
    let shutdown = config.shutdown.clone();

    // Set up the tunnel, unless the client shuts down meanwhile.
    let control_stream = tokio::select! {
        control_stream = set_up_tunnel(&config, &conn) => control_stream?,
        () = shutdown.draining() => {
            CloseCode::Ok.close(&conn, "client shutting down");
            return Ok(());
        }
    };
    METRICS.tunnels.inc();
    let _tunnel_up = Active::new(&METRICS.tunnel_up);

    // Start the keepalive loop to maintain the QUIC connection.
    // This loop periodically sends a PING and expects a PONG response.
    // If the keepalive fails, close the connection, which ends this handler.
    let keepalive_conn = conn.clone();
    let keepalive_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let Err(e) = run_keepalive_client_loop(control_stream, keepalive_shutdown).await;
        if keepalive_conn.close_reason().is_some() {
            return;
        }
        if e.is::<ProtocolViolation>() {
            warn!("Invalid control message, closing the connection: {:#}", e);
            CloseCode::ProtocolViolation.close(&keepalive_conn, "unexpected control message");
        } else {
            METRICS.keepalive_failures.inc();
            warn!("Keepalive failed, closing the connection: {:#}", e);
            CloseCode::KeepaliveFailed.close(&keepalive_conn, "keepalive failed");
        }
    });

    // Accept bidirectional QUIC streams for new forwarded connections, until the connection ends
    // or the client finished shutting down. While draining, streams still arrive for
    // connections the server accepted before it received DRAIN.
    let finished = async {
        shutdown.draining().await;
        info!("Shutting down");
        shutdown.finish_connections().await;
    };
    tokio::pin!(finished);
    let end = loop {
        let (send, recv) = tokio::select! {
            accepted = conn.accept_bi() => match accepted {
                Ok(stream) => stream,
                Err(e) => break e,
            },
            () = &mut finished => {
                CloseCode::Ok.close(&conn, "client shutting down");
                return Ok(());
            }
        };
        METRICS.forwarded_connections.inc();

        let stream_id = recv.id();
        debug!(
            "Opened QUIC stream for new forwarded connection, id {}",
            stream_id
        );

        // Draining the shutdown waits for the connection.
        let config = Arc::clone(&config);
        shutdown.spawn(async move {
            let _active = Active::new(&METRICS.forwarded_connections_active);
            if let Err(e) = forward_tcp_to_quic_stream(config, send, recv).await {
                METRICS.forwarded_connections_aborted.inc();
                info!(
                    "Forwarded connection (stream {}) aborted: {:#}",
                    stream_id, e
                );
            }
        });
    };

    debug!("Closed QUIC connection handler: {}", end);
    if CloseCode::of(&end) == Some(CloseCode::Ok) {
        return Ok(());
    }
    Err(anyhow::Error::new(end).context("connection to the server ended"))
}

/// Authenticates and asks the server to accept external TCP connections on the client's behalf.
/// Returns the control stream.
async fn set_up_tunnel(
    config: &Arc<ClientConfig<ClientAppData>>,
    conn: &quinn::Connection,
) -> Result<BiStream<Compat<quinn::RecvStream>, Compat<quinn::SendStream>>> {
    // We need to prove we know the PSK to authenticate.
    let mut control_stream = handle_quic_auth_client_side(Arc::clone(config), conn.clone())
        .await
        .context("failed to authenticate against PR QUIC server")?;

    // Ask the server to accept external TCP connections on our behalf.
    let requested_port = config.app_data.remote_listen_port;
    let welcome = timeout(
        PortRedirectProtocol::CONFIGURATION_TIMEOUT,
        request_listen_port(
            &mut control_stream,
            &Greeting::new(CLIENT_SOFTWARE, requested_port),
        ),
    )
    .await
    .context("timed out waiting for the server to confirm the listen port")?
    .with_context(|| format!("server did not listen on TCP port {}", requested_port))?;
    let (software, port) = (welcome.software(), welcome.listen_port);
    info!(
        "Tunnel established, server ({:?}) listens on TCP port {}",
        software, port
    );
    Ok(control_stream)
}
