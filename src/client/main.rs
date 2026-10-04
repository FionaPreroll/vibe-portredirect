// PortRedirect Client - Program
//
// License: GPL-3.0-only

use anyhow::{Context, Result};
use std::process::ExitCode;
use tracing::{error, info, span, warn, Level};

use crate::app_data::ClientAppData;
use crate::client::config::Config;
use crate::client::reconnect::Backoff;
use crate::client::run_client::{run_client, ClientSettings};
use crate::get_config_dir;
use crate::host_port::HostPort;
use crate::logging::init_logging;
use crate::quic::client::LocalAddress;
use crate::shutdown::Shutdown;

/// Runs the client program, `portredirect_client`, until a shutdown signal arrives.
#[tokio::main]
pub async fn main() -> ExitCode {
    // Read the command line, the environment and the configuration file.
    let config = Config::from_command_line();

    init_logging(config.log_level, config.log_format, config.log_connections);
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

    // The address to send to the server from: any address, unless one is given.
    let quic_local = match &config.quic_local_host {
        None => LocalAddress::Any {
            port: config.quic_local_port,
        },
        Some(host) => HostPort::new(host, config.quic_local_port)
            .first_address()
            .await
            .map(LocalAddress::Address)
            .with_context(|| format!("failed to resolve the QUIC local address {}", host))?,
    };

    // The server and the destination: names are looked up each time they are used, see
    // HostPort. So a connection attempt fails while the server's name has no address, and a
    // forwarded connection while the destination's name has none, e.g. until its container runs.
    let quic_remote = HostPort::new(config.quic_remote_host, config.quic_remote_port);
    let forward_destination = HostPort::new(config.destination_host, config.destination_port);
    if let Err(e) = forward_destination.lookup().await {
        warn!(
            "The destination {} has no address yet: {}. It is looked up again for each connection.",
            forward_destination, e
        );
    }

    info!(
        destination = %forward_destination,
        local = %quic_local,
        remote = %quic_remote,
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
        quic_local,
        quic_remote,
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
