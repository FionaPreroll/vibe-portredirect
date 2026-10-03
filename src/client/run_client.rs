// PortRedirect Client - Main Binary Entry Point
//
// License: GPL-3.0-only

use super::metrics::start_metrics_server;
use super::server_handler::handle_quic_server_connection;

use crate::app_data::ClientAppData;
use crate::get_config_dir;
use crate::quic::client::{run_quic_client, ClientConfig};

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// Data structure to hold connection statistics.
pub struct ConnectionStats {
    pub connection_count: usize,
}

/// Core function that runs the client logic.
pub async fn run_client(
    app_config: ClientAppData,
    tcp_local_addr: SocketAddr,
    quic_remote_addr: SocketAddr,
    quic_remote_hostname_match: Option<String>,
    max_connections: usize,
    metrics_addr: Option<SocketAddr>,
) -> Result<()> {
    // Shared state for connection statistics.
    let stats = Arc::new(Mutex::new(ConnectionStats {
        connection_count: 0,
    }));

    // Start the metrics server if enabled.
    if let Some(metrics_addr) = metrics_addr {
        tokio::spawn(async move {
            if let Err(e) = start_metrics_server(metrics_addr).await {
                tracing::error!("Metrics server failed: {:#}", e);
            }
        });
    }

    // Spawn a task to periodically print connection stats.
    {
        let stats_clone = Arc::clone(&stats);
        tokio::spawn(async move {
            use tokio::time::{sleep, Duration};
            let mut printed_once = false;
            let mut previous_connection_count = 0;
            loop {
                sleep(Duration::from_secs(1)).await;
                let stats = stats_clone.lock().unwrap();
                if previous_connection_count != stats.connection_count || !printed_once {
                    tracing::info!("Active connections: {}", stats.connection_count);
                    previous_connection_count = stats.connection_count;
                    printed_once = true;
                }
            }
        });
    }

    // Get or create configuration directory.
    let config_dir = get_config_dir(None)?; // HACK: None for now.

    // Build the QUIC client configuration.
    let quic_client_config = ClientConfig::create_default_config(
        config_dir,
        tcp_local_addr,
        quic_remote_addr,
        // Name to verify the server certificate against, defaults to the remote IP address.
        quic_remote_hostname_match,
        Some(max_connections),
        app_config,
    );

    // Run the QUIC client.
    run_quic_client(quic_client_config, handle_quic_server_connection).await?;
    Ok(())
}
