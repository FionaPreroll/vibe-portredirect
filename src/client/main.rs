// PortRedirect Client - Main binary
//
// License: GPL-3.0-only

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser};
use portredirect::app_data::ClientAppData;
use portredirect::client::run_client::run_client;
use portredirect::get_config_dir;
use portredirect::psk::{warn_if_psk_on_command_line, PskArgs};
use portredirect::PortRedirectProtocol;
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

    /// TCP port the server should listen on for external connections.
    /// Must be allowed by the server's --allowed-client-ports.
    #[clap(long)]
    remote_listen_port: u16,

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

    /// Maximum number of concurrently forwarded connections, i.e. connections to the destination.
    #[clap(
        long,
        default_value_t = PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS as u32,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    max_connections: u32,

    /// Name the server's TLS certificate must be issued for (Subject Alt Name), if it differs
    /// from --quic-remote-host. Must match the server's --quic-cert-hostname.
    #[clap(long)]
    quic_remote_hostname_match: Option<String>,

    #[command(flatten)]
    psk: PskArgs,
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
    let matches = Args::command().get_matches();
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    warn_if_psk_on_command_line(&matches);
    let psk = args.psk.load()?;

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
    let app_config = ClientAppData::new(psk, forward_destination, args.remote_listen_port);

    // Ensure the rustls crypto provider is installed.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Run the client.
    run_client(
        app_config,
        quic_local_addr,
        quic_remote_addr,
        args.quic_remote_hostname_match,
        args.max_connections as usize,
        args.provide_metrics,
    )
    .await?;

    Ok(())
}
