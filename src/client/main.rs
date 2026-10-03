// PortRedirect Client - Main binary
//
// License: GPL-3.0-only

use anyhow::{anyhow, Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser};
use portredirect::app_data::ClientAppData;
use portredirect::client::reconnect::Backoff;
use portredirect::client::run_client::{run_client, ClientSettings};
use portredirect::psk::{warn_if_psk_on_command_line, PskArgs};
use portredirect::PortRedirectProtocol;
use portredirect::{get_config_dir, init_logging, shutdown_signal};
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use tracing::level_filters::LevelFilter;
use tracing::{error, info, span, Level};

/// Command-line arguments for the port redirector tool.
///
/// The client reconnects whenever the connection to the server ends. It exits with code 0 on
/// SIGINT or SIGTERM, and with code 1 if it can't work as configured, e.g. because the server
/// rejects its PSK or port.
#[derive(Parser)]
struct Args {
    /// Full path to configuration directory, with the server's certificate cert.der.
    #[clap(long)]
    config_dir: Option<String>,

    /// Destination host for data coming from QUIC connections.
    #[clap(long)]
    destination_host: String,

    /// Destination port (currently TCP only).
    #[clap(long, value_parser = clap::value_parser!(u16).range(1..))]
    destination_port: u16,

    /// TCP port the server should listen on for external connections.
    /// Must be allowed by the server's --allowed-client-ports.
    #[clap(long, value_parser = clap::value_parser!(u16).range(1..))]
    remote_listen_port: u16,

    /// QUIC connection remote host (server).
    #[clap(long)]
    quic_remote_host: String,

    /// QUIC connection remote port (server).
    #[clap(long, value_parser = clap::value_parser!(u16).range(1..))]
    quic_remote_port: u16,

    /// QUIC connection local host to bind to (client).
    #[clap(long, default_value = "0.0.0.0")]
    quic_local_host: String,

    /// QUIC connection local port to bind to (client).
    #[clap(long, default_value = "0")]
    quic_local_port: u16,

    /// Serve Prometheus metrics via HTTP at /metrics, see --metrics-listen.
    #[clap(long)]
    provide_metrics: bool,

    /// Address and port for --provide-metrics. The endpoint has no authentication, only make it
    /// reachable from trusted networks.
    #[clap(long, default_value = "127.0.0.1:9898")]
    metrics_listen: SocketAddr,

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

    /// Log messages up to this level: off, error, warn, info, debug or trace.
    #[clap(long, default_value = "info")]
    log_level: LevelFilter,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Parse command-line arguments.
    let matches = Args::command().get_matches();
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    init_logging(args.log_level);
    let _enter = span!(Level::INFO, "prclient_main").entered();

    warn_if_psk_on_command_line(&matches);

    // Exit code 0 after a shutdown signal, 1 if the client can't work as configured.
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{:#}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<()> {
    let psk = args.psk.load()?;

    // Get or create configuration directory.
    let config_dir =
        get_config_dir(args.config_dir).context("Failed to get configuration directory")?;
    info!("Configuration directory: {:?}", config_dir);

    // Resolve local UDP bind address.
    let quic_local_addr = resolve_socket_addr(&args.quic_local_host, args.quic_local_port)
        .context("resolving QUIC local address")?;

    // Resolve remote UDP server address.
    let quic_remote_addr = resolve_socket_addr(&args.quic_remote_host, args.quic_remote_port)
        .context("resolving QUIC remote address")?;

    // Resolve the forward destination for the tunneled TCP connections.
    let forward_destination = resolve_socket_addr(&args.destination_host, args.destination_port)
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
        app_data: ClientAppData::new(psk, forward_destination, args.remote_listen_port),
        config_dir,
        quic_local_addr,
        quic_remote_addr,
        quic_remote_hostname_match: args.quic_remote_hostname_match,
        max_connections: args.max_connections as usize,
        metrics_addr: args.provide_metrics.then_some(args.metrics_listen),
        reconnect_backoff: Backoff::default(),
    };
    run_client(settings, shutdown_signal()).await
}

/// Resolves `host` and `port` to a socket address.
fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("{} has no address", host))
}
