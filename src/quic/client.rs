// PortRedirect Common Client Code
//
// License: GPL-3.0-only
// Based on: Quinn example code (originally licensed under Apache-2.0/MIT)
// Original: https://github.com/quinn-rs/quinn/blob/204b14792b5e92eb2c43cdb1ff05426412ff4466/quinn/examples/client.rs

use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use std::time::Duration;
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};
use tracing::info;

use super::{client_transport_config, ALPN_QUIC_PORTREDIRECT};
use crate::protocol::close::CloseCode;
use crate::shutdown::Shutdown;
use crate::PortRedirectProtocol;

/// Time to wait for the server to be notified when the client closes its connections.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub struct ClientConfig<AppDataType> {
    pub remote_hostname_match: Option<String>,
    pub ca_path: Option<PathBuf>,
    pub cert_file: PathBuf,

    pub local_socket: SocketAddr,
    pub remote_socket: SocketAddr,
    /// Maximum number of concurrently forwarded connections, i.e. streams the server may open.
    /// Defaults to `PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS`.
    pub connection_limit: Option<usize>,

    /// When to shut down, and the forwarded connections that may finish meanwhile.
    pub shutdown: Shutdown,

    pub app_data: AppDataType,
}

impl<AppDataType> ClientConfig<AppDataType> {
    pub fn create_default_config(
        config_dir: PathBuf,
        local_socket: SocketAddr,
        remote_socket: SocketAddr,
        remote_hostname_match: Option<String>,
        connection_limit: Option<usize>,
        app_data: AppDataType,
    ) -> Self {
        ClientConfig {
            remote_hostname_match,
            ca_path: None,
            cert_file: config_dir.join("cert.der"),
            local_socket,
            remote_socket,
            connection_limit,
            shutdown: Shutdown::default(),
            app_data,
        }
    }
}

/// A QUIC client endpoint, which can connect to the server repeatedly.
pub struct QuicClient<AppDataType> {
    config: Arc<ClientConfig<AppDataType>>,
    endpoint: quinn::Endpoint,
    server_name: String,
}

impl<AppDataType> QuicClient<AppDataType> {
    /// Loads the server certificate to trust and binds the local endpoint.
    ///
    /// Prerequisite: A rustls CryptoProvider must be available before calling this function,
    /// call CryptoProvider::install_default() before this point.
    pub fn new(config: ClientConfig<AppDataType>) -> Result<Self> {
        info!("Starting PR QUIC client setup");

        // Trust the CA chain, or if none is given, the server's certificate.
        let certificate_path = config.ca_path.as_ref().unwrap_or(&config.cert_file);
        let certificate = fs::read(certificate_path).with_context(|| {
            format!(
                "failed to read the server certificate {}, copy cert.der from the server's configuration directory",
                certificate_path.display()
            )
        })?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificate))
            .with_context(|| format!("invalid certificate {}", certificate_path.display()))?;

        // Crypto setup.
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.alpn_protocols = ALPN_QUIC_PORTREDIRECT.iter().map(|&x| x.into()).collect();

        // QUIC client setup.
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
        client_config.transport_config(Arc::new(client_transport_config(
            config
                .connection_limit
                .unwrap_or(PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS),
        )));

        let mut endpoint = quinn::Endpoint::client(config.local_socket)
            .with_context(|| format!("failed to bind {}", config.local_socket))?;
        endpoint.set_default_client_config(client_config);

        let server_name = config
            .remote_hostname_match
            .clone()
            .unwrap_or_else(|| config.remote_socket.ip().to_string());

        Ok(Self {
            config: Arc::new(config),
            endpoint,
            server_name,
        })
    }

    pub fn config(&self) -> &Arc<ClientConfig<AppDataType>> {
        &self.config
    }

    /// Connects to the server, or rather: establishes the tunnel's QUIC connection.
    pub async fn connect(&self) -> Result<quinn::Connection> {
        let start = Instant::now();
        info!(
            server_name_match = self.server_name,
            local = self.config.local_socket.to_string(),
            remote = self.config.remote_socket.to_string(),
            "Connecting to PR QUIC Server"
        );
        let connection = self
            .endpoint
            .connect(self.config.remote_socket, &self.server_name)?
            .await
            .context("failed to connect")?;
        info!("PR QUIC connection established in {:?}.", start.elapsed());
        Ok(connection)
    }

    /// Closes all connections and waits until the server has been notified, but not longer
    /// than `SHUTDOWN_TIMEOUT`.
    pub async fn shutdown(&self, reason: &str) {
        self.endpoint.close(CloseCode::Ok.code(), reason.as_bytes());
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, self.endpoint.wait_idle()).await;
    }
}

/// Connects to the server once and runs `handle_incoming` for the connection, for tests.
///
/// Returns the handler's result.
///
/// Prerequisite: A rustls CryptoProvider must be available before calling this function,
/// call CryptoProvider::install_default() before this point.
#[cfg(test)]
#[cfg_attr(not(coverage), tracing::instrument(skip(config, handle_incoming)))]
pub async fn run_quic_client<F, Fut, AppDataType>(
    config: ClientConfig<AppDataType>,
    handle_incoming: F,
) -> Result<()>
where
    F: Fn(Arc<ClientConfig<AppDataType>>, quinn::Connection) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let client = QuicClient::new(config)?;
    let connection = client.connect().await?;

    let start = Instant::now();
    let result = handle_incoming(Arc::clone(client.config()), connection).await;
    info!("PR QUIC connection terminated after {:?}.", start.elapsed());
    result
}
