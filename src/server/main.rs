// PortRedirect Server
//
// License: GPL-3.0-only

use anyhow::{anyhow, Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser};
use portredirect::app_data::ServerAppData;
use portredirect::psk::{warn_if_psk_on_command_line, PskArgs};
use portredirect::quic::server::{run_quic_server, ServerConfig};
use portredirect::server::client_handler::handle_quic_client_connection;
use portredirect::server::metrics_printer::print_metrics_loop;
use portredirect::server::{ForwardingLimits, PortSpec};
use portredirect::PortRedirectProtocol;
use portredirect::{get_config_dir, init_logging};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tracing::level_filters::LevelFilter;
use tracing::{info, span, Level};

/// Command-line arguments for the server side.
#[derive(Parser, Debug)]
struct Args {
    /// Full path to configuration directory.
    #[clap(long)]
    config_dir: Option<String>,

    /// TCP listener host for external connections
    #[clap(long)]
    local_host: String,

    /// TCP listener port for external connections (deprecated, use --allowed-client-ports instead).
    #[clap(long)]
    local_port: Option<u16>,

    /// Allowed ports for clients to request, e.g., "80,443,1000-2000"
    #[clap(long, value_delimiter = ',')]
    allowed_client_ports: Option<Vec<PortSpec>>,

    /// QUIC server listener host.
    #[clap(long, default_value = "127.0.0.1")]
    quic_server_host: String,

    /// QUIC server listener port.
    #[clap(long, default_value = "4433")]
    quic_server_port: u16,

    /// QUIC server certificate Subject Alt Name.
    #[clap(long, default_value = "127.0.0.1")]
    quic_cert_hostname: String,

    #[command(flatten)]
    psk: PskArgs,

    /// Maximum number of concurrent QUIC connections, including connections that are not
    /// authenticated yet. Each client uses one.
    #[clap(
        long,
        default_value_t = DEFAULT_MAX_QUIC_CONNECTIONS,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    max_quic_connections: u32,

    /// Maximum number of concurrently forwarded TCP connections per client.
    /// Further connections wait until one ends.
    #[clap(
        long,
        default_value_t = PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS as u32,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    max_connections: u32,

    /// Maximum number of concurrently forwarded TCP connections per external IP address
    /// (IPv6: per /64 network), 0 for no limit. Further connections are closed right away.
    #[clap(long, default_value_t = ForwardingLimits::DEFAULT_MAX_CONNECTIONS_PER_IP as u32)]
    max_connections_per_ip: u32,

    /// Close forwarded TCP connections after this many seconds without data transfer,
    /// 0 to never close idle connections.
    #[clap(long, default_value_t = ForwardingLimits::DEFAULT_IDLE_TIMEOUT.as_secs())]
    idle_timeout: u64,

    /// Print metrics to stderr every second, if any value changes.
    #[clap(long)]
    print_metrics: bool,

    /// Log messages up to this level: off, error, warn, info, debug or trace.
    #[clap(long, default_value = "info")]
    log_level: LevelFilter,
}

/// Default for --max-quic-connections.
const DEFAULT_MAX_QUIC_CONNECTIONS: u32 = 64;

/// Program entry point.
#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments.
    let matches = Args::command().get_matches();
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    init_logging(args.log_level);

    // Create a root span for logging.
    let _root_span = span!(Level::INFO, "prserver_main").entered();

    // Install the default crypto provider for rustls.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    warn_if_psk_on_command_line(&matches);
    let psk = args.psk.load()?;

    // Retrieve (or create) the configuration directory.
    let config_dir =
        get_config_dir(args.config_dir).context("Failed to get configuration directory")?;
    info!("Configuration directory: {:?}", config_dir);

    // Parse local TCP listener address(es) #TODO remove legacy handler.
    let allowed_client_ports = {
        let mut allowed_client_ports = args.allowed_client_ports.unwrap_or_default();
        if let Some(local_port) = args.local_port {
            info!("--local-port is deprecated; use --allowed-client-ports instead");
            // add given port to allowed ports
            allowed_client_ports.append(&mut vec![PortSpec::Single(local_port)]);
        }
        allowed_client_ports
    };
    if allowed_client_ports.is_empty() {
        return Err(anyhow!("--allowed-client-ports is required"));
    }

    // Parse QUIC server listener address.
    let quic_addr = resolve_socket_addr(&format!(
        "{}:{}",
        args.quic_server_host, args.quic_server_port
    ))
    .context("Failed to resolve QUIC bind address")?;

    // Set up QUIC server configuration.
    let forwarding_limits = ForwardingLimits {
        max_connections: args.max_connections as usize,
        max_connections_per_ip: args.max_connections_per_ip as usize,
        idle_timeout: (args.idle_timeout > 0).then(|| Duration::from_secs(args.idle_timeout)),
    };
    let app_data = ServerAppData::new(psk, args.local_host, allowed_client_ports)
        .with_forwarding_limits(forwarding_limits);
    info!("QUIC will listen on {}", quic_addr);

    let quic_config = ServerConfig::create_default_config(
        config_dir,
        args.quic_cert_hostname,
        quic_addr,
        Some(args.max_quic_connections as usize),
        app_data.clone(),
    );

    // Spawn the metrics printer task.
    if args.print_metrics {
        info!("Starting metrics printer task");
        tokio::spawn(async {
            print_metrics_loop().await;
        });
    }

    // Start QUIC server.
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
