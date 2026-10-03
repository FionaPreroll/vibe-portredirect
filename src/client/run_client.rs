// PortRedirect Client - Main Binary Entry Point
//
// License: GPL-3.0-only

use super::metrics::start_metrics_server;
use super::reconnect::{is_permanent_error, Backoff};
use super::server_handler::handle_quic_server_connection;

use crate::app_data::ClientAppData;
use crate::protocol::close::CloseCode;
use crate::quic::client::{ClientConfig, QuicClient};

use anyhow::{Context, Result};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{error, info, warn};

/// After a connection worked for this long, reconnecting starts again with the initial delay.
const STABLE_CONNECTION_DURATION: Duration = Duration::from_secs(60);

/// Settings of the client, see the command-line options of `portredirect_client`.
pub struct ClientSettings {
    pub app_data: ClientAppData,
    /// Directory with the server's certificate `cert.der`.
    pub config_dir: PathBuf,
    pub quic_local_addr: SocketAddr,
    pub quic_remote_addr: SocketAddr,
    /// Name the server's certificate must be issued for, defaults to the remote IP address.
    pub quic_remote_hostname_match: Option<String>,
    /// Maximum number of concurrently forwarded connections.
    pub max_connections: usize,
    /// Address to serve Prometheus metrics on, if any.
    pub metrics_addr: Option<SocketAddr>,
    /// Delays between reconnection attempts.
    pub reconnect_backoff: Backoff,
}

/// Runs the client: connects to the server and reconnects whenever the connection ends, with
/// growing delays, until `shutdown` completes.
///
/// Returns `Ok` after `shutdown` completed, and an error if the client can't work without a
/// change of the configuration, e.g. because the server rejected the PSK or the requested port,
/// or the server's certificate is missing or doesn't match.
pub async fn run_client(
    settings: ClientSettings,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    // Start the metrics server if enabled.
    if let Some(metrics_addr) = settings.metrics_addr {
        tokio::spawn(async move {
            if let Err(e) = start_metrics_server(metrics_addr).await {
                error!("Metrics server failed: {:#}", e);
            }
        });
    }

    // Build the QUIC client.
    let quic_client_config = ClientConfig::create_default_config(
        settings.config_dir,
        settings.quic_local_addr,
        settings.quic_remote_addr,
        settings.quic_remote_hostname_match,
        Some(settings.max_connections),
        settings.app_data,
    );
    let client = QuicClient::new(quic_client_config)?;

    let mut backoff = settings.reconnect_backoff;
    tokio::pin!(shutdown);
    loop {
        let attempt = tokio::select! {
            attempt = run_connection(&client) => attempt,
            () = &mut shutdown => break,
        };

        let error = match (attempt.result, &attempt.close_reason) {
            (Ok(()), Some(reason)) => anyhow::anyhow!("the server ended the tunnel: {}", reason),
            (Ok(()), None) => anyhow::anyhow!("the server ended the tunnel"),
            (Err(e), _) => e,
        };
        if is_permanent_error(&error, attempt.close_reason.as_ref()) {
            client.shutdown("client giving up").await;
            return Err(error.context("connecting again would fail the same way, giving up"));
        }

        if attempt
            .connected_for
            .is_some_and(|duration| duration >= STABLE_CONNECTION_DURATION)
        {
            backoff.reset();
        }
        let delay = backoff.next_delay();
        warn!(
            "Disconnected from the server: {:#}. Reconnecting in {:.1?}",
            error, delay
        );

        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = &mut shutdown => break,
        }
    }

    info!("Shutting down");
    client.shutdown("client shutting down").await;
    Ok(())
}

/// Result of one connection to the server.
struct ConnectionAttempt {
    result: Result<()>,
    /// Why the connection was closed, if it was established.
    close_reason: Option<quinn::ConnectionError>,
    /// How long the connection was established, if it was.
    connected_for: Option<Duration>,
}

/// Connects to the server and handles the connection until it ends.
async fn run_connection(client: &QuicClient<ClientAppData>) -> ConnectionAttempt {
    let connection = match client.connect().await {
        Ok(connection) => connection,
        Err(e) => {
            return ConnectionAttempt {
                result: Err(e),
                close_reason: None,
                connected_for: None,
            }
        }
    };

    let connected = Instant::now();
    let result = handle_quic_server_connection(Arc::clone(client.config()), connection.clone())
        .await
        .context("tunnel failed");

    // Don't leave the connection open, e.g. if the handler failed on its own.
    if connection.close_reason().is_none() {
        CloseCode::InternalError.close(&connection, "client error");
    }

    ConnectionAttempt {
        result,
        close_reason: connection.close_reason(),
        connected_for: Some(connected.elapsed()),
    }
}
