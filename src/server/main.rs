// PortRedirect Server
//
// License: GPL-3.0-only

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use portredirect::app_data::ServerAppData;
use portredirect::get_config_dir;
use portredirect::quic::server::{run_quic_server, ServerConfig};
use portredirect::server::client_handler::handle_quic_client_connection;
use portredirect::server::metrics_printer::print_metrics_loop;
use portredirect::server::PortSpec;
use secrecy::SecretString;
use std::net::{SocketAddr, ToSocketAddrs};
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

    /// Pre-shared key for authentication over QUIC.
    #[clap(long)]
    quic_psk: SecretString,

    /// Print metrics to stderr every second, if any value changes.
    #[clap(long)]
    print_metrics: bool,
}

/// Program entry point.
#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();

    // Create a root span for logging.
    let _root_span = span!(Level::INFO, "prserver_main").entered();

    // Install the default crypto provider for rustls.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Parse command-line arguments.
    let args = Args::parse();

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
    let app_data = ServerAppData::new(args.quic_psk, args.local_host, allowed_client_ports);
    info!("QUIC will listen on {}", quic_addr);

    let quic_config = ServerConfig::create_default_config(
        config_dir,
        args.quic_cert_hostname,
        quic_addr,
        None,
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

/// Sets up tracing for logging.
fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_target(true)
        .with_line_number(true)
        .init();
}

/// Resolves a socket address from a string.
fn resolve_socket_addr(addr: &str) -> Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("Unable to resolve address: {}", addr))
}
