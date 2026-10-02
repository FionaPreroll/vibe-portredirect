// PortRedirect Client - Main binary
//
// License: GPL-3.0-only

use anyhow::{Context, Result};
use clap::Parser;
use portredirect::app_data::ClientAppData;
use portredirect::client::run_client::run_client;
use portredirect::get_config_dir;
use secrecy::SecretString;
use std::net::ToSocketAddrs;
use tracing::{info, span, Level};

/// Command-line arguments for the port redirector tool.
#[derive(Parser)]
struct Args {
    /// Destination host for data coming from QUIC connections.
    #[clap(long)]
    destination_host: String,

    /// Destination port (currently TCP only).
    #[clap(long)]
    destination_port: u16,

    /// QUIC connection remote host (server).
    #[clap(long)]
    quic_remote_host: String,

    /// QUIC connection remote port (server).
    #[clap(long)]
    quic_remote_port: u16,

    /// QUIC connection local host to bind to (client).
    #[clap(long, default_value = "0.0.0.0")]
    quic_local_host: String,

    /// QUIC connection local port to bind to (client).
    #[clap(long, default_value = "0")]
    quic_local_port: u16,

    /// Enable Prometheus metrics.
    #[clap(long)]
    provide_metrics: bool,

    /// QUIC remote hostname override for Subject Alt Name match in TLS cert.
    #[clap(long)]
    quic_remote_hostname_match: Option<String>,

    /// Pre-shared key for authentication over QUIC.
    #[clap(long)]
    quic_psk: SecretString,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging.
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_target(true)
        .with_line_number(true)
        .init();

    let _enter = span!(Level::INFO, "prclient_main").entered();

    // Parse command-line arguments.
    let args = Args::parse();

    // Get or create configuration directory.
    let config_dir = get_config_dir(None)?; // HACK None for now.
    info!("Configuration directory: {:?}", config_dir);

    // Construct the destination address for tunneled TCP connections.
    let destination_addr = format!("{}:{}", args.destination_host, args.destination_port);

    // Resolve local UDP bind address.
    let quic_local_addr = format!("{}:{}", args.quic_local_host, args.quic_local_port)
        .to_socket_addrs()
        .context("constructing QUIC local address")?
        .next()
        .expect("Unable to resolve local address");

    // Resolve remote UDP server address.
    let quic_remote_addr = format!("{}:{}", args.quic_remote_host, args.quic_remote_port)
        .to_socket_addrs()
        .context("constructing QUIC remote address")?
        .next()
        .expect("Unable to resolve remote address");

    info!(
        destination = %destination_addr,
        local = %quic_local_addr,
        remote = %quic_remote_addr,
        "Initializing QUIC Client"
    );

    // Resolve the forward destination for the tunneled TCP connections.
    let forward_destination = destination_addr
        .to_socket_addrs()
        .context("resolving destination address")?
        .next()
        .context("resolving destination address")?;

    // Build the application configuration.
    let app_config = ClientAppData::new(args.quic_psk, forward_destination);

    // Ensure the rustls crypto provider is installed.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Run the client.
    run_client(
        app_config,
        quic_local_addr,
        quic_remote_addr,
        args.provide_metrics,
    )
    .await?;

    Ok(())
}
