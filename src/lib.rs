// PortRedirect
//
// License: GPL-3.0-only

use anyhow::{Context, Result};
use std::{path::PathBuf, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing::{info, warn};

pub mod app_data;
pub mod bi_stream;
pub mod client;
pub mod forward;
pub mod limits;
pub mod metrics_helper;
pub mod private_files;
pub mod protocol;
pub mod psk;
pub mod quic;
pub mod server;

/// Returns the path to the configuration directory, creating it if necessary.
pub fn get_config_dir(override_config_dir: Option<String>) -> Result<PathBuf> {
    // Use the override if provided, otherwise fall back to the platform's config directory.
    let config_dir = if let Some(override_path) = override_config_dir {
        PathBuf::from(override_path)
    } else {
        let mut config_dir =
            dirs::config_dir().context("Failed to find your platform's config directory")?;
        config_dir.push("portredirect");
        config_dir
    };

    // Create the directory if it doesn't exist. It holds the private key, so keep it private.
    private_files::create_private_dir_all(&config_dir).context("create config dir")?;

    Ok(config_dir)
}

/// Sets up logging to stdout for messages up to `max_level`.
pub fn init_logging(max_level: LevelFilter) {
    tracing_subscriber::fmt()
        .with_max_level(max_level)
        .with_target(true)
        .with_line_number(true)
        .init();
}

/// Completes when the process receives SIGINT (Ctrl-C) or SIGTERM.
pub async fn shutdown_signal() {
    let interrupt = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("Failed to listen for SIGINT: {}", e);
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(e) => {
                warn!("Failed to listen for SIGTERM: {}", e);
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => info!("Received SIGINT"),
        () = terminate => info!("Received SIGTERM"),
    }
}

pub struct PortRedirectProtocol;

impl PortRedirectProtocol {
    pub const CONNECTION_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
    pub const CONNECTION_KEEPALIVE_READ_TIMEOUT: Duration = Duration::from_secs(30);
    pub const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);
    pub const CONFIGURATION_TIMEOUT: Duration = Duration::from_secs(10);
    /// Interval of QUIC keep-alive packets, below QUIC's default idle timeout of 30 seconds.
    pub const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(25);
    /// Default maximum number of concurrently forwarded connections per tunnel.
    pub const DEFAULT_MAX_FORWARDED_CONNECTIONS: usize = 512;

    // TODO choose these values non-arbitrarily
    pub const QUIC_STREAM_READ_BUFFER_SIZE: usize = 64 * 1024; // 64 KiB
    pub const QUIC_CRYPTO_BUFFER_SIZE: usize = 64 * 1024;
}

pub type ByteCount = u64;
