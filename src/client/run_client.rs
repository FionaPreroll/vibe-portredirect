// PortRedirect Client - Main Binary Entry Point
//
// License: GPL-3.0-only

use super::metrics::METRICS;
use super::reconnect::{is_permanent_error, Backoff};
use super::server_handler::handle_quic_server_connection;

use crate::app_data::ClientAppData;
use crate::metrics::serve_metrics;
use crate::protocol::close::CloseCode;
use crate::protocol::message::ProtocolViolation;
use crate::quic::client::{ClientConfig, QuicClient};
use crate::shutdown::Shutdown;

use anyhow::{Context, Result};
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
    pub quic_cert_hostname: Option<String>,
    /// Maximum number of concurrently forwarded connections.
    pub max_connections: usize,
    /// Address to serve Prometheus metrics on, if any.
    pub metrics_addr: Option<SocketAddr>,
    /// Delays between reconnection attempts.
    pub reconnect_backoff: Backoff,
    /// When to shut down, and the forwarded connections that may finish meanwhile.
    pub shutdown: Shutdown,
}

/// Runs the client: connects to the server and reconnects whenever the connection ends, with
/// growing delays, until the settings' shutdown drains. Then the running forwarded connections
/// may finish, see [`handle_quic_server_connection`].
///
/// Returns `Ok` after shutting down, and an error if the client can't work without a change of
/// the configuration, e.g. because the server rejected the PSK or the requested port, or the
/// server's certificate is missing or doesn't match.
pub async fn run_client(settings: ClientSettings) -> Result<()> {
    // Start the metrics server if enabled.
    if let Some(metrics_addr) = settings.metrics_addr {
        tokio::spawn(async move {
            let Err(e) = serve_metrics(METRICS.registry.clone(), metrics_addr).await;
            error!("Metrics server failed: {:#}", e);
        });
    }

    // Build the QUIC client.
    let shutdown = settings.shutdown;
    let mut quic_client_config = ClientConfig::create_default_config(
        settings.config_dir,
        settings.quic_local_addr,
        settings.quic_remote_addr,
        settings.quic_cert_hostname,
        Some(settings.max_connections),
        settings.app_data,
    );
    quic_client_config.shutdown = shutdown.clone();
    let client = QuicClient::new(quic_client_config)?;

    let mut backoff = settings.reconnect_backoff;
    loop {
        // Ends after the connection finished shutting down, if the client shuts down.
        let attempt = run_connection(&client).await;
        if shutdown.is_draining() {
            break;
        }

        let error = match (attempt.result, &attempt.close_reason) {
            (Ok(()), Some(reason)) => anyhow::anyhow!("the server ended the tunnel: {}", reason),
            (Ok(()), None) => anyhow::anyhow!("the server ended the tunnel"),
            (Err(e), _) => e,
        };
        if is_permanent_error(&error, attempt.close_reason.as_ref()) {
            client.shutdown("client giving up").await;
            let replaced =
                attempt.close_reason.as_ref().and_then(CloseCode::of) == Some(CloseCode::Replaced);
            return Err(error.context(if replaced {
                "another client with the same name took over the port, not connecting again"
            } else {
                "connecting again would fail the same way, giving up"
            }));
        }

        let delay = reconnect_delay(&mut backoff, attempt.connected_for);
        warn!(
            "Disconnected from the server: {:#}. Reconnecting in {:.1?}",
            error, delay
        );

        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = shutdown.draining() => break,
        }
    }

    info!("Shut down");
    client.shutdown("client shutting down").await;
    Ok(())
}

/// Returns the delay before connecting again, after a connection that was established for
/// `connected_for`, if at all. After a connection that worked for a while, the delays start over.
fn reconnect_delay(backoff: &mut Backoff, connected_for: Option<Duration>) -> Duration {
    if connected_for.is_some_and(|duration| duration >= STABLE_CONNECTION_DURATION) {
        backoff.reset();
    }
    backoff.next_delay()
}

/// Result of one connection to the server.
struct ConnectionAttempt {
    result: Result<()>,
    /// Why the connection was closed, if it was established.
    close_reason: Option<quinn::ConnectionError>,
    /// How long the connection was established, if it was.
    connected_for: Option<Duration>,
}

/// Connects to the server and handles the connection until it ends, or until the client shut
/// down.
async fn run_connection(client: &QuicClient<ClientAppData>) -> ConnectionAttempt {
    METRICS.connection_attempts.inc();
    let connected = tokio::select! {
        connected = client.connect() => connected,
        () = client.config().shutdown.draining() => Err(anyhow::anyhow!("shutting down")),
    };
    let connection = match connected {
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
        let violation = result
            .as_ref()
            .is_err_and(|e| e.chain().any(|cause| cause.is::<ProtocolViolation>()));
        if violation {
            CloseCode::ProtocolViolation.close(&connection, "unexpected message");
        } else {
            CloseCode::InternalError.close(&connection, "client error");
        }
    }

    ConnectionAttempt {
        result,
        close_reason: connection.close_reason(),
        connected_for: Some(connected.elapsed()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backoff() -> Backoff {
        Backoff::new(Duration::from_secs(1), Duration::from_secs(60))
    }

    #[test]
    fn test_delays_grow_while_connections_fail_or_end_soon() {
        let mut backoff = backoff();
        for connected_for in [None, Some(Duration::from_secs(5)), None] {
            reconnect_delay(&mut backoff, connected_for);
        }
        // The fourth delay is 8 seconds, minus up to half for jitter.
        assert!(reconnect_delay(&mut backoff, None) >= Duration::from_secs(4));
    }

    #[test]
    fn test_delays_start_over_after_a_stable_connection() {
        let mut backoff = backoff();
        for _ in 0..5 {
            reconnect_delay(&mut backoff, None);
        }
        // E.g. after a network outage ended a connection that worked for a day.
        let delay = reconnect_delay(&mut backoff, Some(STABLE_CONNECTION_DURATION));
        assert!(delay <= Duration::from_secs(1), "{:?}", delay);
    }
}
