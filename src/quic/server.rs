// PortRedirect Common Server Code
//
// License: GPL-3.0-only
// Based on: Quinn example code (originally licensed under Apache-2.0/MIT)
// Original: https://github.com/quinn-rs/quinn/blob/204b14792b5e92eb2c43cdb1ff05426412ff4466/quinn/examples/server.rs

use anyhow::{anyhow, Context, Error, Result};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::timeout;
use tracing::{debug, info, instrument, warn};

use crate::limits::QuicAdmission;
use crate::private_files::{warn_if_accessible_by_others, write_private_file};
use crate::protocol::close::CloseCode;
use crate::quic::fingerprint::CertFingerprint;
use crate::quic::{configure_transport_config, ALPN_QUIC_PORTREDIRECT};
use crate::server::metrics::{RefusalReason, METRICS};
use crate::shutdown::Shutdown;

/// Minimum time between two warnings about the connection limit.
const LIMIT_WARNING_INTERVAL: Duration = Duration::from_secs(60);

/// Time to wait for clients to be notified when the server closes all connections.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Time a client has to complete the TLS handshake, see [`ServerConfig::handshake_timeout`].
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The server's certificate in its configuration directory.
const CERT_FILE: &str = "cert.der";

/// The private key of the server's certificate in its configuration directory.
const KEY_FILE: &str = "key.der";

/// Configuration for the QUIC server.
///
/// This struct holds the necessary configuration parameters for setting up a QUIC server.
///
/// # Fields
///
/// * `cert_hostname` - The hostname for the certificate to use or generate.
/// * `cert_file` - The path to the certificate to use or generate.
/// * `key_file` - The path to the private key file to use or generate.
/// * `listen` - Bind address for the QUIC server.
/// * `stateless_retry` - Whether to enable stateless retry.
/// * `connection_limit` - Optional limit on the number of concurrent QUIC connections, including
///   connections that are not authenticated yet.
/// * `admission` - Limits per client address and blocking after failed authentication attempts.
/// * `handshake_timeout` - Time a client has to complete the TLS handshake. Longer handshakes,
///   e.g. stalled on purpose, are aborted and count as failed attempts.
/// * `app_data` - Application-specific data.
#[derive(Debug)]
pub struct ServerConfig<AppDataType> {
    pub cert_hostname: String,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub listen: SocketAddr,
    pub stateless_retry: bool,
    pub connection_limit: Option<usize>,
    pub admission: QuicAdmission,
    pub handshake_timeout: Duration,
    /// When to shut down, and the forwarded connections that may finish meanwhile.
    pub shutdown: Shutdown,
    pub app_data: AppDataType,
}

impl<AppDataType> ServerConfig<AppDataType> {
    /// Creates a default server configuration.
    ///
    /// This function initializes a `ServerConfig` with default values, using the provided parameters or defaults.
    ///
    /// # Arguments
    ///
    /// * `config_dir` - The directory where the certificate and key files are located.
    /// * `cert_alt_name` - The Subject Alternae Name (SAN) for the QUIC server certificate.
    /// * `bind_socket` - Bind address for the QUIC server.
    /// * `connection_limit` - Optionally, the maximum number of concurrent connections to allow.
    /// * `app_data` - Optionally, any application-specific data.
    ///
    /// # Returns
    ///
    /// Returns a `ServerConfig` instance with the specified and/or default parameters.
    pub fn create_default_config(
        config_dir: PathBuf,
        cert_alt_name: String,
        bind_socket: SocketAddr,
        connection_limit: Option<usize>,
        app_data: AppDataType,
    ) -> Self {
        ServerConfig {
            cert_hostname: cert_alt_name,
            cert_file: config_dir.join(CERT_FILE),
            key_file: config_dir.join(KEY_FILE),
            listen: bind_socket,
            stateless_retry: true, // Be more secure by default
            connection_limit,
            admission: QuicAdmission::default(),
            handshake_timeout: HANDSHAKE_TIMEOUT,
            shutdown: Shutdown::default(),
            app_data,
        }
    }
}

/// Loads or generates a QUIC-compatible certificate and private key.
///
/// This function attempts to load a certificate and private key from the specified file paths.
/// If neither file exists, it generates a self-signed certificate and saves it to the paths.
/// If only one of them exists, it fails instead of replacing that file: a new certificate would
/// lock out all clients that trust the old one.
///
/// # Arguments
///
/// * `cert_alt_name` - The Subject Alternate Name (SAN) for the certificate (only used at key creation).
/// * `key_path` - The path to the private key file to load, if it exists, or to save the generated key to if it does not.
/// * `cert_path` - The path to the certificate file, same applies.
///
/// # Returns
///
/// Returns a `Result` containing a tuple:
/// * `Vec<CertificateDer<'static>>` - The parsed certificate chain as DER-encoded certificates.
/// * `PrivateKeyDer<'static>` - The parsed private key in a QUIC-compatible format.
///
/// On success, the tuple contains the certificate chain and private key. On failure,
/// it returns an `anyhow::Error` describing the issue encountered during file
/// reading, parsing or generation.
#[instrument()]
pub fn load_or_generate_quic_cert(
    cert_alt_name: String,
    key_path: PathBuf,
    cert_path: PathBuf,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    match (key_path.exists(), cert_path.exists()) {
        (true, true) => load_quic_cert(key_path, cert_path),
        (false, false) => generate_quic_cert(cert_alt_name, key_path, cert_path),
        (true, false) => Err(anyhow!(
            "found the private key {} but not the certificate {}: restore the certificate, or delete the private key to generate a new certificate, which clients then need",
            key_path.display(),
            cert_path.display()
        )),
        (false, true) => Err(anyhow!(
            "found the certificate {} but not the private key {}: restore the private key, or delete the certificate to generate a new one, which clients then need",
            cert_path.display(),
            key_path.display()
        )),
    }
}

/// Returns the fingerprint of the server's certificate in `config_dir`. Like the server when it
/// starts, generates the certificate first if there is none, issued for `cert_alt_name`.
pub fn cert_fingerprint(config_dir: &Path, cert_alt_name: String) -> Result<CertFingerprint> {
    let (cert_chain, _key) = load_or_generate_quic_cert(
        cert_alt_name,
        config_dir.join(KEY_FILE),
        config_dir.join(CERT_FILE),
    )?;
    let certificate = cert_chain.first().context("no certificate")?;
    Ok(CertFingerprint::of(certificate))
}

/// Loads a QUIC-compatible certificate and private key from the specified file paths.
///
/// This function reads a private key and certificate chain from the provided file paths
/// and attempts to parse them into the required QUIC-compatible formats. It supports
/// both DER-encoded and PEM-encoded files. DER files must have the `.der` extension,
/// otherwise PEM is assumed.
///
/// Note: Ensure that the file paths provided are accessible and have the correct permissions.
/// A warning is logged if the private key file is accessible by other users.
///
/// # Arguments
///
/// * `key_path` - The path to the private key file.
/// * `cert_path` - The path to the certificate chain file.
///
/// # Returns
///
/// Returns a `Result` containing a tuple with the certificate chain and private key,
/// in a format suitable for quinn.
#[instrument()]
pub fn load_quic_cert(
    key_path: PathBuf,
    cert_path: PathBuf,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Try loading
    let key = fs::read(key_path.clone()).context("failed to read private key")?;
    warn_if_accessible_by_others(&key_path);
    let key = if key_path.extension().is_some_and(|x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        PrivateKeyDer::from_pem_slice(&key).context("malformed or missing PEM private key")?
    };
    let cert_chain = fs::read(cert_path.clone()).context("failed to read certificate chain")?;
    let cert_chain = if cert_path.extension().is_some_and(|x| x == "der") {
        vec![CertificateDer::from(cert_chain)]
    } else {
        CertificateDer::pem_slice_iter(&cert_chain)
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?
    };

    Ok((cert_chain, key))
}

/// Generates a self-signed certificate and private key.
///
/// This function generates a self-signed certificate using the provided alternative
/// name for the certificate (e.g., a domain name or IP address). The generated files are saved
/// to the specified paths, the private key readable only by its owner (on Unix). The function
/// then loads the certificate and private key into QUIC-compatible formats.
///
/// Note: This function is suitable for development and testing purposes. For production,
/// use a trusted certificate authority to issue certificates.
///
/// # Arguments
///
/// * `cert_alt_name` - The alternative name for the certificate.
/// * `key_path` - The path to save the private key.
/// * `cert_path` - The path to save the certificate.
///
/// # Returns
///
/// Returns a `Result` containing a tuple:
/// * `Vec<CertificateDer<_>>` - The parsed certificate chain as DER-encoded certificates.
/// * `PrivateKeyDer<_>` - The parsed private key in a QUIC-compatible format.
///
/// On success, the tuple contains the certificate chain and private key. On failure,
/// it returns an `anyhow::Error` describing the issue encountered during file reading,
/// writing, or parsing.
#[instrument()]
pub fn generate_quic_cert(
    cert_alt_name: String,
    key_path: PathBuf,
    cert_path: PathBuf,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    info!("generating self-signed certificate");
    let cert = rcgen::generate_simple_self_signed(vec![cert_alt_name.clone()])
        .with_context(|| format!("failed to generate a certificate for {:?}", cert_alt_name))?;
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert = CertificateDer::from(cert.cert);

    // Write private key and certificate to files. If that fails, remove what was written, so the
    // next start can generate a new pair instead of finding only one of them.
    if let Err(e) = write_private_file(&key_path, key.secret_pkcs8_der()) {
        let _ = fs::remove_file(&key_path);
        return Err(e).context("failed to write private key");
    }
    if let Err(e) = fs::write(&cert_path, &cert) {
        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_file(&cert_path);
        return Err(e).context("failed to write certificate");
    }

    Ok((vec![cert], key.into()))
}

/// Runs the QUIC server with the specified configuration and client handler.
///
/// The server accepts connections and runs `handle_incoming_client` for each in its own task,
/// until `config.shutdown` drains. Then it accepts no new connections, and the handlers are
/// expected to start no new forwarded connections, while running ones may finish within the
/// shutdown timeout. Then, or when the shutdown stops, the server closes all connections, so
/// clients notice right away.
///
/// Prerequisite: A rustls CryptoProvider must be available before calling this function,
/// call CryptoProvider::install_default() before this point.
///
/// Fails if the certificate can't be loaded or generated, or the endpoint can't be bound.
#[cfg_attr(
    not(coverage),
    tracing::instrument(skip(config, handle_incoming_client))
)]
pub async fn run_quic_server<F, Fut, AppDataType>(
    config: ServerConfig<AppDataType>,
    handle_incoming_client: F,
) -> Result<()>
where
    F: Fn(Arc<ServerConfig<AppDataType>>, quinn::Connection) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), Error>> + Send + 'static,
    AppDataType: Send + Sync + 'static,
{
    info!("Starting PR QUIC server setup");

    // Load or generate certificate.
    let (cert_chain, key_der) = load_or_generate_quic_cert(
        config.cert_hostname.clone(),
        config.key_file.clone(),
        config.cert_file.clone(),
    )
    .context("loading or generating cert")?;
    let fingerprint = CertFingerprint::of(cert_chain.first().context("no certificate")?);
    info!(
        "Certificate fingerprint, for the clients' --quic-cert-fingerprint: {}",
        fingerprint
    );

    info!(
        "Configuring rustls server ({} certs, key: {:?})",
        cert_chain.len(),
        key_der
    );

    // Crypto setup.
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .context("rustls ServerConfig builder")?;
    server_crypto.alpn_protocols = ALPN_QUIC_PORTREDIRECT.iter().map(|&x| x.into()).collect();

    // QUIC server setup.
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    configure_transport_config(transport_config);

    // Start QUIC server listener.
    info!(listen_addr = %config.listen, "Binding QUIC endpoint");
    let endpoint = quinn::Endpoint::server(server_config, config.listen)?;

    // PR QUIC server side loop:
    // Handle incoming QUIC connections forever.
    let start = Instant::now();
    let config = Arc::from(config);
    let handle_incoming_client = Arc::new(handle_incoming_client);
    let mut last_limit_warning: Option<Instant> = None;
    let shutdown = config.shutdown.clone();
    info!("QUIC server is ready and accepting connections");
    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
            () = shutdown.draining() => break,
        };
        let remote = incoming.remote_address();

        if config.admission.is_blocked(remote.ip()) {
            // Refusing is cheap, it happens before the TLS handshake.
            debug!("Refusing connection from {}: address is blocked", remote);
            METRICS.refused(RefusalReason::Blocked);
            incoming.refuse();
        } else if config
            .connection_limit
            .is_some_and(|n| endpoint.open_connections() >= n)
        {
            // Warn at most once a minute, so floods don't flood the log.
            if last_limit_warning.is_none_or(|last| last.elapsed() >= LIMIT_WARNING_INTERVAL) {
                warn!(
                    "Refusing connections: open connection limit ({}) reached",
                    config.connection_limit.unwrap_or_default()
                );
                last_limit_warning = Some(Instant::now());
            }
            debug!(
                "Refusing connection from {}: connection limit reached",
                remote
            );
            METRICS.refused(RefusalReason::ConnectionLimit);
            incoming.refuse();
        } else if config.stateless_retry && !incoming.remote_address_validated() {
            debug!(
                "Requiring connection from {} to validate its address",
                remote
            );
            incoming.retry().unwrap();
        } else {
            // Limit the connections per address. The address is validated at this point.
            let Some(address_slot) = config.admission.try_acquire(remote.ip()) else {
                debug!(
                    "Refusing connection from {}: too many connections from this address",
                    remote
                );
                METRICS.refused(RefusalReason::AddressLimit);
                incoming.refuse();
                continue;
            };

            // The TLS handshake runs in the connection's own task, so a client that stalls it
            // can't hold up other clients.
            let config = Arc::clone(&config);
            let handle_incoming_client = Arc::clone(&handle_incoming_client);
            tokio::spawn(async move {
                let handshake_timeout = config.handshake_timeout;
                let connection = match timeout(handshake_timeout, incoming).await {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(e)) => {
                        config.admission.record_failure(remote.ip());
                        METRICS.authentication_failures.inc();
                        warn!(
                            "Failed to accept incoming QUIC connection from {}: {}",
                            remote, e
                        );
                        return;
                    }
                    Err(_) => {
                        // Dropping the handshake closes the connection.
                        config.admission.record_failure(remote.ip());
                        METRICS.authentication_failures.inc();
                        warn!(
                            "TLS handshake with {} not completed within {:?}, closing the connection",
                            remote, handshake_timeout
                        );
                        return;
                    }
                };

                debug!(peer = %remote, "Accepting new QUIC client connection at {:?}", start.elapsed());
                if let Err(e) = handle_incoming_client(Arc::clone(&config), connection).await {
                    warn!("Incoming connection dropped: {:#}", e)
                }
                // The connection no longer counts for its address.
                drop(address_slot);
            });
        }
    }

    if shutdown.is_draining() {
        info!("Shutting down, accepting no new connections");
        // Clients that connect meanwhile notice right away, and try again later.
        let refusing = tokio::spawn(refuse_connections(endpoint.clone()));
        shutdown.finish_connections().await;
        refusing.abort();
        endpoint.close(CloseCode::Ok.code(), b"server shutting down");
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, endpoint.wait_idle()).await;
    }

    info!("PR QUIC server terminated after {:?}.", start.elapsed());

    Ok(())
}

/// Refuses all new connections, e.g. while the server shuts down.
async fn refuse_connections(endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        let remote = incoming.remote_address();
        debug!("Refusing connection from {}: shutting down", remote);
        METRICS.refused(RefusalReason::ShuttingDown);
        incoming.refuse();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_pem_encoded_cert_and_key() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        fs::write(&cert_path, generated.cert.pem())?;
        fs::write(&key_path, generated.signing_key.serialize_pem())?;

        let (cert_chain, key) = load_quic_cert(key_path, cert_path)?;

        assert_eq!(cert_chain.len(), 1);
        assert_eq!(cert_chain[0].as_ref(), generated.cert.der().as_ref());
        assert_eq!(key.secret_der(), generated.signing_key.serialize_der());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_generated_private_key_is_owner_only() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir()?;
        let cert_path = temp_dir.path().join("cert.der");
        let key_path = temp_dir.path().join("key.der");

        generate_quic_cert("localhost".into(), key_path.clone(), cert_path)?;

        assert_eq!(fs::metadata(&key_path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    /// Returns the paths of a key and a certificate in `dir`, which don't exist yet.
    fn cert_paths(dir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        (dir.path().join("key.der"), dir.path().join("cert.der"))
    }

    #[test]
    fn test_generated_certificate_is_loaded_on_next_start() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let (key_path, cert_path) = cert_paths(&temp_dir);

        let (generated_chain, generated_key) =
            load_or_generate_quic_cert("localhost".into(), key_path.clone(), cert_path.clone())?;
        let (loaded_chain, loaded_key) =
            load_or_generate_quic_cert("other-name".into(), key_path, cert_path)?;

        // Clients trust the first certificate, so it must not change.
        assert_eq!(loaded_chain, generated_chain);
        assert_eq!(loaded_key.secret_der(), generated_key.secret_der());
        Ok(())
    }

    #[test]
    fn test_missing_key_is_an_error_and_keeps_the_certificate() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let (key_path, cert_path) = cert_paths(&temp_dir);
        generate_quic_cert("localhost".into(), key_path.clone(), cert_path.clone())?;
        let certificate = fs::read(&cert_path)?;
        fs::remove_file(&key_path)?;

        let err =
            load_or_generate_quic_cert("localhost".into(), key_path.clone(), cert_path.clone())
                .unwrap_err();

        assert!(
            err.to_string().contains("restore the private key"),
            "{}",
            err
        );
        assert_eq!(fs::read(&cert_path)?, certificate);
        assert!(!key_path.exists());
        Ok(())
    }

    #[test]
    fn test_missing_certificate_is_an_error_and_keeps_the_key() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let (key_path, cert_path) = cert_paths(&temp_dir);
        generate_quic_cert("localhost".into(), key_path.clone(), cert_path.clone())?;
        let key = fs::read(&key_path)?;
        fs::remove_file(&cert_path)?;

        let err =
            load_or_generate_quic_cert("localhost".into(), key_path.clone(), cert_path.clone())
                .unwrap_err();

        assert!(
            err.to_string().contains("restore the certificate"),
            "{}",
            err
        );
        assert_eq!(fs::read(&key_path)?, key);
        assert!(!cert_path.exists());
        Ok(())
    }

    #[test]
    fn test_invalid_certificate_name_is_an_error() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let (key_path, cert_path) = cert_paths(&temp_dir);

        // DNS names must be ASCII.
        let err = generate_quic_cert("bücher.example".into(), key_path.clone(), cert_path.clone())
            .unwrap_err();

        assert!(err.to_string().contains("bücher.example"), "{}", err);
        assert!(!key_path.exists() && !cert_path.exists());
        Ok(())
    }

    #[test]
    fn test_failed_generation_leaves_no_files_behind() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let key_path = temp_dir.path().join("key.der");
        // Writing the certificate fails, after the private key was written.
        let cert_path = temp_dir.path().join("missing-directory").join("cert.der");

        assert!(generate_quic_cert("localhost".into(), key_path.clone(), cert_path).is_err());

        assert!(!key_path.exists(), "the private key was left behind");
        Ok(())
    }

    #[test]
    fn test_failed_key_write_leaves_the_certificate_alone() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        // Writing the private key fails, before the certificate is written.
        let key_path = temp_dir.path().join("missing-directory").join("key.der");
        let cert_path = temp_dir.path().join("cert.der");
        fs::write(&cert_path, b"existing certificate")?;

        assert!(generate_quic_cert("localhost".into(), key_path, cert_path.clone()).is_err());

        assert_eq!(fs::read(&cert_path)?, b"existing certificate");
        Ok(())
    }

    #[test]
    fn test_fingerprint_of_the_certificate_in_the_configuration_directory() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;

        // Generated first, if there is no certificate yet, then loaded.
        let generated = cert_fingerprint(temp_dir.path(), "localhost".into())?;
        let certificate = fs::read(temp_dir.path().join(CERT_FILE))?;
        assert_eq!(generated, CertFingerprint::of(&certificate));
        assert_eq!(
            cert_fingerprint(temp_dir.path(), "other".into())?,
            generated
        );

        // Like the server, it doesn't replace a certificate whose key is missing.
        fs::remove_file(temp_dir.path().join(KEY_FILE))?;
        assert!(cert_fingerprint(temp_dir.path(), "localhost".into()).is_err());
        assert_eq!(fs::read(temp_dir.path().join(CERT_FILE))?, certificate);
        Ok(())
    }

    #[test]
    fn test_load_missing_files_fails() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let (key_path, cert_path) = cert_paths(&temp_dir);

        let err = load_quic_cert(key_path, cert_path).unwrap_err();

        assert!(err.to_string().contains("private key"), "{}", err);
        Ok(())
    }

    #[test]
    fn test_load_pem_without_key_fails() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        fs::write(&cert_path, generated.cert.pem())?;
        fs::write(&key_path, generated.cert.pem())?; // a certificate is not a key

        assert!(load_quic_cert(key_path, cert_path).is_err());
        Ok(())
    }
}
