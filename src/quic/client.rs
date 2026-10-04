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

use super::fingerprint::{CertFingerprint, FingerprintVerifier};
use super::{bind_endpoint, client_transport_config, CongestionControl, ALPN_QUIC_PORTREDIRECT};
use crate::protocol::close::CloseCode;
use crate::shutdown::Shutdown;
use crate::PortRedirectProtocol;

/// Time to wait for the server to be notified when the client closes its connections.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub struct ClientConfig<AppDataType> {
    pub remote_hostname_match: Option<String>,
    /// The server's certificate to trust, unless `cert_fingerprints` are given.
    pub cert_file: PathBuf,
    /// Fingerprints of the server certificates to trust instead of `cert_file`, whatever names
    /// they are issued for.
    pub cert_fingerprints: Vec<CertFingerprint>,

    pub local_socket: SocketAddr,
    pub remote_socket: SocketAddr,
    /// Maximum number of concurrently forwarded connections, i.e. streams the server may open.
    /// Defaults to `PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS`.
    pub connection_limit: Option<usize>,
    /// How fast the client sends.
    pub congestion_control: CongestionControl,

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
            cert_file: config_dir.join("cert.der"),
            cert_fingerprints: Vec::new(),
            local_socket,
            remote_socket,
            connection_limit,
            congestion_control: CongestionControl::default(),
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
    /// Loads the server certificate to trust, unless its fingerprints are given, and binds the
    /// local endpoint.
    ///
    /// Prerequisite: A rustls CryptoProvider must be available before calling this function,
    /// call CryptoProvider::install_default() before this point.
    pub fn new(config: ClientConfig<AppDataType>) -> Result<Self> {
        info!("Starting PR QUIC client setup");

        let mut client_crypto = if config.cert_fingerprints.is_empty() {
            // Trust the server's certificate, issued for the server's name.
            let certificate_path = &config.cert_file;
            let certificate = fs::read(certificate_path).with_context(|| {
                format!(
                    "failed to read the server certificate {}, copy cert.der from the server's configuration directory or trust it by its fingerprint with --quic-cert-fingerprint",
                    certificate_path.display()
                )
            })?;
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from(certificate))
                .with_context(|| format!("invalid certificate {}", certificate_path.display()))?;
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        } else {
            let fingerprints = config.cert_fingerprints.clone();
            let trusted: Vec<String> = fingerprints.iter().map(ToString::to_string).collect();
            let trusted = trusted.join(", ");
            info!(
                "Trusting server certificates with the fingerprints {}",
                trusted
            );
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(FingerprintVerifier::new(fingerprints)))
                .with_no_client_auth()
        };
        client_crypto.alpn_protocols = ALPN_QUIC_PORTREDIRECT.iter().map(|&x| x.into()).collect();

        // QUIC client setup.
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
        client_config.transport_config(Arc::new(client_transport_config(
            config
                .connection_limit
                .unwrap_or(PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS),
            config.congestion_control,
        )));

        let mut endpoint = bind_endpoint(config.local_socket, None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use std::net::Ipv4Addr;

    /// Presents the same certificate to every client, and signs with a key that may not belong
    /// to it.
    #[derive(Debug)]
    struct FixedCertificate(Arc<CertifiedKey>);

    impl ResolvesServerCert for FixedCertificate {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    /// Returns a QUIC server endpoint that presents `certificate` and signs with `key`.
    fn server_endpoint(
        certificate: &rcgen::CertifiedKey<rcgen::KeyPair>,
        key: &rcgen::KeyPair,
    ) -> Result<quinn::Endpoint> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let key = rustls::crypto::ring::default_provider()
            .key_provider
            .load_private_key(key)?;
        let presented = CertifiedKey::new(vec![certificate.cert.der().clone()], key);
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCertificate(Arc::new(presented))));
        crypto.alpn_protocols = ALPN_QUIC_PORTREDIRECT.iter().map(|&x| x.into()).collect();
        let config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        Ok(quinn::Endpoint::server(config, local)?)
    }

    /// Connects to a server that presents `certificate` and signs with `key`. The client trusts
    /// certificates with `fingerprints`, has no copy of the certificate and expects a name the
    /// certificate isn't issued for.
    async fn connect(
        certificate: &rcgen::CertifiedKey<rcgen::KeyPair>,
        key: &rcgen::KeyPair,
        fingerprints: Vec<CertFingerprint>,
    ) -> Result<()> {
        let server = server_endpoint(certificate, key)?;
        let empty_dir = tempfile::tempdir()?;
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let name = Some("another-name".to_string());
        let config_dir = empty_dir.path().to_path_buf();
        let mut config = ClientConfig::create_default_config(
            config_dir,
            local,
            server.local_addr()?,
            name,
            None,
            (),
        );
        config.cert_fingerprints = fingerprints;
        let client = QuicClient::new(config)?;
        let accept = async {
            if let Some(incoming) = server.accept().await {
                let _ = incoming.await;
            }
        };
        let ((), connected) = tokio::join!(accept, client.connect());
        connected?.close(0u8.into(), b"done");
        Ok(())
    }

    fn generate() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap()
    }

    #[tokio::test]
    async fn test_client_trusts_a_certificate_by_its_fingerprint() -> Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (server, other) = (generate(), generate());
        let key = &server.signing_key;
        let fingerprint = CertFingerprint::of(server.cert.der());
        let other_fingerprint = CertFingerprint::of(other.cert.der());

        // One of several fingerprints is enough, e.g. while the certificate changes.
        connect(&server, key, vec![other_fingerprint, fingerprint]).await?;

        let err = connect(&server, key, vec![other_fingerprint]).await;
        let err = format!("{:#}", err.unwrap_err());
        assert!(err.contains(&fingerprint.to_string()), "{}", err);
        let expected = "isn't one of --quic-cert-fingerprint";
        assert!(err.contains(expected), "{}", err);
        Ok(())
    }

    #[tokio::test]
    async fn test_server_with_the_certificate_but_not_its_key_is_rejected() -> Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (pinned, attacker) = (generate(), generate());
        let fingerprint = CertFingerprint::of(pinned.cert.der());

        // E.g. someone who copied cert.der, but has no access to key.der.
        let result = connect(&pinned, &attacker.signing_key, vec![fingerprint]).await;

        let err = format!("{:#}", result.unwrap_err());
        assert!(err.contains("BadSignature"), "{}", err);
        Ok(())
    }
}
