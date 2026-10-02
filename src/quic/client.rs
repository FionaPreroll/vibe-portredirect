// PortRedirect Common Client Code
//
// License: GPL-3.0-only
// Based on: Quinn example code (originally licensed under Apache-2.0/MIT)
// Original: https://github.com/quinn-rs/quinn/blob/204b14792b5e92eb2c43cdb1ff05426412ff4466/quinn/examples/client.rs

use anyhow::{anyhow, Error, Result};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use std::{fs, io, net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};
use tracing::{debug, error, info, instrument};


use super::ALPN_QUIC_PORTREDIRECT;

#[derive(Debug)]
#[allow(unused)]
pub struct ClientConfig<AppDataType> {
    pub remote_hostname_match: Option<String>,
    pub ca_path: Option<PathBuf>,
    pub cert_file: PathBuf,

    pub local_socket: SocketAddr,
    pub remote_socket: SocketAddr,
    pub connection_limit: Option<usize>,

    pub app_data: AppDataType,
}

impl<AppDataType> ClientConfig<AppDataType> {
    #[allow(unused)]
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
            app_data,
        }
    }
}

/// Prerequisite: A rustls CryptoProvider must be available before calling this function,
/// call CryptoProvider::install_default() before this point.
#[instrument(skip(config, handle_incoming))]
pub async fn run_quic_client<F, Fut, AppDataType>(
    config: ClientConfig<AppDataType>,
    handle_incoming: F,
) -> Result<(), Error>
where
    F: Fn(Arc<ClientConfig<AppDataType>>, quinn::Connection) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), Error>> + Send + 'static,
{
    info!("Starting PR QUIC client setup");

    // Load CA chain, or if none is given, load cert file.
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca_path) = &config.ca_path {
        roots.add(CertificateDer::from(fs::read(ca_path)?))?;
    } else {
        let cert_file_result = fs::read(&config.cert_file);

        match cert_file_result {
            Ok(cert) => {
                roots.add(CertificateDer::from(cert))?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("local server certificate not found");
            }
            Err(e) => {
                error!("failed to open local server certificate: {}", e);
            }
        }
    }

    // Crypto setup.
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = ALPN_QUIC_PORTREDIRECT.iter().map(|&x| x.into()).collect();

    let server_name_match = config
        .remote_hostname_match
        .clone()
        .unwrap_or_else(|| config.remote_socket.ip().to_string());

    // QUIC client setup.
    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));

    let mut endpoint = quinn::Endpoint::client(config.local_socket)?;
    endpoint.set_default_client_config(client_config);

    // Connect, or rather: establish tunnel.
    let start = Instant::now();
    info!(
        server_name_match,
        local = config.local_socket.to_string(),
        remote = config.remote_socket.to_string(),
        "Connecting to PR QUIC Server"
    );
    let connection = endpoint
        .connect(config.remote_socket, server_name_match.as_str())?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    debug!("QUIC connected at {:?}", start.elapsed());

    // PR QUIC client side loop:
    // Handle incoming streams forever.
    let config = Arc::from(config);
    info!("PR QUIC connection established in {:?}.", start.elapsed());
    let fut = handle_incoming(Arc::clone(&config), connection);
    let task = tokio::spawn(async move {
        if let Err(e) = fut.await {
            error!("connection failed: {reason}", reason = e.to_string())
        }
    });

    task.await?;
    info!("PR QUIC connection terminated after {:?}.", start.elapsed());

    Ok(())
}
