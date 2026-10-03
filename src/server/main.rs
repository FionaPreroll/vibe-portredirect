// PortRedirect Server
//
// License: GPL-3.0-only

use anyhow::{anyhow, Context, Result};
use portredirect::app_data::ServerAppData;
use portredirect::quic::server::{run_quic_server, ServerConfig};
use portredirect::server::client_handler::handle_quic_client_connection;
use portredirect::server::config::Config;
use portredirect::server::metrics_printer::print_metrics_loop;
use portredirect::shutdown::Shutdown;
use portredirect::{get_config_dir, init_logging};
use std::net::{SocketAddr, ToSocketAddrs};
use tracing::{info, span, Level};

/// Program entry point.
#[tokio::main]
async fn main() -> Result<()> {
    // Read the command line, the environment and the configuration file.
    let config = Config::from_command_line();

    init_logging(config.log_level);

    // Create a root span for logging.
    let _root_span = span!(Level::INFO, "prserver_main").entered();

    // Install the default crypto provider for rustls.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    if let Some(config_file) = &config.config_file {
        info!("Configuration file: {:?}", config_file);
    }
    let clients = config.clients.load()?;

    // Retrieve (or create) the configuration directory.
    let config_dir =
        get_config_dir(config.config_dir).context("Failed to get configuration directory")?;
    info!("Configuration directory: {:?}", config_dir);

    // Parse QUIC server listener address.
    let quic_addr = resolve_socket_addr(&format!(
        "{}:{}",
        config.quic_listen_host, config.quic_listen_port
    ))
    .context("Failed to resolve QUIC bind address")?;

    // Set up QUIC server configuration.
    let app_data = ServerAppData::with_clients(clients, config.listen_host)
        .with_forwarding_limits(config.forwarding_limits);
    info!("QUIC will listen on {}", quic_addr);

    let mut quic_config = ServerConfig::create_default_config(
        config_dir,
        config.quic_cert_hostname,
        quic_addr,
        Some(config.max_quic_connections),
        app_data.clone(),
    );
    quic_config.shutdown = Shutdown::on_signals(config.shutdown_timeout);

    // Spawn the metrics printer task.
    if config.print_metrics {
        info!("Starting metrics printer task");
        tokio::spawn(async {
            print_metrics_loop().await;
        });
    }

    // Start QUIC server, until a shutdown signal arrives.
    run_quic_server(quic_config, handle_quic_client_connection)
        .await
        .with_context(|| "PortRedirect Server Error")?;

    info!("PortRedirect Server exited cleanly");
    Ok(())
}

/// Resolves a socket address from a string.
fn resolve_socket_addr(addr: &str) -> Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("Unable to resolve address: {}", addr))
}
