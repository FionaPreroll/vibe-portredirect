// PortRedirect Client - Program
//
// License: GPL-3.0-only

use anyhow::{anyhow, Context, Result};
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use tracing::{error, info, span, Level};

use crate::app_data::ClientAppData;
use crate::client::config::Config;
use crate::client::reconnect::Backoff;
use crate::client::run_client::{run_client, ClientSettings};
use crate::shutdown::Shutdown;
use crate::{get_config_dir, init_logging};

/// Runs the client program, `portredirect_client`, until a shutdown signal arrives.
#[tokio::main]
pub async fn main() -> ExitCode {
    // Read the command line, the environment and the configuration file.
    let config = Config::from_command_line();

    init_logging(config.log_level);
    let _enter = span!(Level::INFO, "prclient_main").entered();

    // Exit code 0 after a shutdown signal, 1 if the client can't work as configured.
    match run(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{:#}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run(config: Config) -> Result<()> {
    if let Some(config_file) = &config.config_file {
        info!("Configuration file: {:?}", config_file);
    }
    let psk = config.psk.load()?;

    // Get or create configuration directory.
    let config_dir =
        get_config_dir(config.config_dir).context("Failed to get configuration directory")?;
    info!("Configuration directory: {:?}", config_dir);

    // Resolve local UDP bind address.
    let quic_local_addr = resolve_socket_addr(&config.quic_local_host, config.quic_local_port)
        .context("resolving QUIC local address")?;

    // Resolve remote UDP server address.
    let quic_remote_addr = resolve_socket_addr(&config.quic_remote_host, config.quic_remote_port)
        .context("resolving QUIC remote address")?;

    // Resolve the forward destination for the tunneled TCP connections.
    let forward_destination =
        resolve_socket_addr(&config.destination_host, config.destination_port)
            .context("resolving destination address")?;

    info!(
        destination = %forward_destination,
        local = %quic_local_addr,
        remote = %quic_remote_addr,
        "Initializing QUIC Client"
    );

    // Ensure the rustls crypto provider is installed.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Run the client until a shutdown signal arrives.
    let settings = ClientSettings {
        app_data: ClientAppData::new(psk, forward_destination, config.remote_listen_port)
            .with_client_name(config.client_name),
        config_dir,
        quic_local_addr,
        quic_remote_addr,
        quic_cert_hostname: config.quic_cert_hostname,
        cert_fingerprints: config.quic_cert_fingerprints,
        max_connections: config.max_connections,
        congestion_control: config.congestion_control,
        metrics_addr: config.metrics_addr,
        reconnect_backoff: Backoff::default(),
        shutdown: Shutdown::on_signals(config.shutdown_timeout),
    };
    run_client(settings).await
}

/// Resolves `host` and `port` to a socket address.
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("{} has no address", host))
}
