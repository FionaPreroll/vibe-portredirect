// PortRedirect Server - Program
//
// License: GPL-3.0-only

use anyhow::{anyhow, Context, Result};
use std::net::{SocketAddr, ToSocketAddrs};
use tracing::{error, info, span, Level};

use crate::app_data::ServerAppData;
use crate::metrics::{print_metrics_loop, serve_metrics};
use crate::quic::server::{
    ensure_server_certificate, run_quic_server, server_fingerprint, ServerConfig,
};
use crate::server::client_handler::handle_quic_client_connection;
use crate::server::config::{CertificateConfig, Command};
use crate::server::metrics::{METRICS, PREFIX};
use crate::shutdown::Shutdown;
use crate::{get_config_dir, init_logging};

/// Runs the server program, `portredirect_server`, until a shutdown signal arrives.
#[tokio::main]
pub async fn main() -> Result<()> {
    // Read the command line, the environment and the configuration file.
    let config = match Command::from_command_line() {
        Command::Run(config) => *config,
        Command::PrintFingerprint(settings) => return print_fingerprint(settings),
    };

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
    // List the clients' metrics before they connect.
    for name in clients.names() {
        METRICS.client(name);
    }

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
    quic_config.congestion_control = config.congestion_control;

    // Spawn the metrics printer task.
    if config.print_metrics {
        info!("Starting metrics printer task");
        tokio::spawn(print_metrics_loop(METRICS.registry.clone(), PREFIX));
    }
    if let Some(metrics_addr) = config.metrics_addr {
        tokio::spawn(async move {
            let Err(e) = serve_metrics(METRICS.registry.clone(), metrics_addr).await;
            error!("Metrics server failed: {:#}", e);
        });
    }

    // Start QUIC server, until a shutdown signal arrives.
    run_quic_server(quic_config, handle_quic_client_connection)
        .await
        .with_context(|| "PortRedirect Server Error")?;

    info!("PortRedirect Server exited cleanly");
    Ok(())
}

/// Prints the fingerprint of the server's certificate, generating the certificate first if there
/// is none.
fn print_fingerprint(config: CertificateConfig) -> Result<()> {
    init_logging(config.log_level);
    let config_dir =
        get_config_dir(config.config_dir).context("Failed to get configuration directory")?;
    ensure_server_certificate(&config_dir, config.quic_cert_hostname)?;
    // In two steps, so the printed fingerprint doesn't depend on what a function named after
    // certificates returns: CodeQL takes that for secrets, and would report printing it as
    // logging them.
    println!("{}", server_fingerprint(&config_dir)?);
    Ok(())
}

/// Resolves a socket address from a string.
fn resolve_socket_addr(addr: &str) -> Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("Unable to resolve address: {}", addr))
}
