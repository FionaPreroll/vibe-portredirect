// PortRedirect Common Server Code
//
// License: GPL-3.0-only
// Based on: Quinn example code (originally licensed under Apache-2.0/MIT)
// Original: https://github.com/quinn-rs/quinn/blob/204b14792b5e92eb2c43cdb1ff05426412ff4466/quinn/examples/server.rs

use anyhow::{Context, Error, Result};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, info, instrument, warn};

use crate::limits::QuicAdmission;
use crate::private_files::{warn_if_accessible_by_others, write_private_file};
use crate::protocol::close::CloseCode;
use crate::quic::{configure_transport_config, ALPN_QUIC_PORTREDIRECT};

/// Minimum time between two warnings about the connection limit.
const LIMIT_WARNING_INTERVAL: Duration = Duration::from_secs(60);

/// Time to wait for clients to be notified when the server shuts down.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

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
            cert_file: config_dir.join("cert.der"),
            key_file: config_dir.join("key.der"),
            listen: bind_socket,
            stateless_retry: true, // Be more secure by default
            connection_limit,
            admission: QuicAdmission::default(),
            app_data,
        }
    }
}

/// Loads or generates a QUIC-compatible certificate and private key.
///
/// This function attempts to load a certificate and private key from the specified file paths.
/// If the files do not exist, it generates a self-signed certificate and saves it to the paths.
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
/// reading or parsing.
///
/// # Examples
///
/// ```rust
/// use std::path::PathBuf;
/// use anyhow::{Result, ensure};
/// use tempfile::TempDir;
/// use portredirect::quic::server::load_or_generate_quic_cert;
///
/// fn main() -> Result<()> {
///     // Set up a temporary directory for testing.
///     let temp_dir = TempDir::new()?;
///     let cert_path = temp_dir.path().join("test_cert.der");
///     let key_path = temp_dir.path().join("test_key.der");
///
///     println!("Trying to load non-existent test files: cert {:?}, key {:?}", cert_path, key_path);
///
///     let result = load_or_generate_quic_cert("localhost".into(), key_path.clone(), cert_path.clone());
///
///     // Assert that no error is returned
///     assert!(result.is_ok(), "Expected no error for nonexistent files");
///
///     // Validate that the certificate and key files were written.
///     ensure!(
///         cert_path.exists(),
///         "Certificate file was not created at {:?}",
///         cert_path
///     );
///     ensure!(
///         key_path.exists(),
///         "Private key file was not created at {:?}",
///         key_path
///     );
///
///     Ok(())
/// }
/// ```
///
#[instrument()]
pub fn load_or_generate_quic_cert(
    cert_alt_name: String,
    key_path: PathBuf,
    cert_path: PathBuf,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if key_path.exists() && cert_path.exists() {
        load_quic_cert(key_path, cert_path)
    } else {
        generate_quic_cert(cert_alt_name, key_path, cert_path)
    }
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
///
/// # Examples
///
/// ```rust
/// use std::path::PathBuf;
/// use anyhow::Result;
/// use tempfile::TempDir;
/// use portredirect::quic::server::load_quic_cert;
///
/// fn main() -> Result<()> {
///     // Set up a temporary directory for testing.
///     let temp_dir = TempDir::new()?;
///     let cert_path = temp_dir.path().join("test_cert.der");
///     let key_path = temp_dir.path().join("test_key.der");
///
///     println!("Trying to load non-existent test files: cert {:?}, key {:?}", cert_path, key_path);
///
///     let result = load_quic_cert(key_path, cert_path);
///
///     // Assert that an error is returned
///     assert!(result.is_err(), "Expected an error for nonexistent files");
///
///     Ok(())
/// }
/// ```
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
///
/// # Examples
///
/// ```rust
/// use std::fs;
/// use std::path::PathBuf;
/// use tempfile::TempDir;
/// use anyhow::{ensure, Context, Result};
/// use rcgen::{generate_simple_self_signed, KeyPair, CertifiedKey};
/// use portredirect::quic::server::generate_quic_cert;
///
/// fn main() -> Result<()> {
///     // Set up a temporary directory for testing.
///     let temp_dir = TempDir::new()?;
///     let cert_path = temp_dir.path().join("test_cert.der");
///     let key_path = temp_dir.path().join("test_key.der");
///
///     println!("Test files: cert {:?}, key {:?}", cert_path, key_path);
///
///     // Generate the self-signed certificate and private key.
///     let (cert_chain, private_key) = generate_quic_cert("localhost".into(), key_path.clone(), cert_path.clone())?;
///
///     // Validate that the certificate and key files were written.
///     ensure!(
///         cert_path.exists(),
///         "Certificate file was not created at {:?}",
///         cert_path
///     );
///     ensure!(
///         key_path.exists(),
///         "Private key file was not created at {:?}",
///         key_path
///     );
///
///     // Load and verify the written certificate and key.
///     let loaded_cert = fs::read(&cert_path).context("failed to read certificate")?;
///     let loaded_key = fs::read(&key_path).context("failed to read private key")?;
///
///     // Ensure the loaded values match the returned outputs.
///     ensure!(
///         loaded_cert == cert_chain[0].as_ref(),
///         "Loaded certificate does not match generated certificate"
///     );
///     ensure!(
///         loaded_key == private_key.secret_der(),
///         "Loaded private key does not match generated key"
///     );
///
///     println!("Certificate and key successfully generated and verified!");
///
///     Ok(())
/// }
/// ```
#[instrument()]
pub fn generate_quic_cert(
    cert_alt_name: String,
    key_path: PathBuf,
    cert_path: PathBuf,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    info!("generating self-signed certificate");
    let cert = rcgen::generate_simple_self_signed(vec![cert_alt_name]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    // Write certificate and private key to files.
    let cert = CertificateDer::from(cert.cert);
    fs::write(&cert_path, &cert).context("failed to write certificate")?;
    write_private_file(&key_path, key.secret_pkcs8_der()).context("failed to write private key")?;

    Ok((vec![cert], key.into()))
}

/// Runs the QUIC server with the specified configuration and client handler.
///
/// This function sets up and runs a QUIC server using the provided configuration and
/// client connection handler. It handles incoming connections and spawns tasks to
/// process them.
///
/// Prerequisite: A rustls CryptoProvider must be available before calling this function,
/// call CryptoProvider::install_default() before this point.
///
/// # Arguments
///
/// * `config` - The server configuration.
/// * `handle_incoming_client` - A function to handle incoming client connections.
///
/// # Returns
///
/// TODO Returns a `Result` indicating the success or failure of the server operation.
pub async fn run_quic_server<F, Fut, AppDataType>(
    config: ServerConfig<AppDataType>,
    handle_incoming_client: F,
) -> Result<()>
where
    F: Fn(Arc<ServerConfig<AppDataType>>, quinn::Connection) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), Error>> + Send + 'static,
{
    run_quic_server_until(config, handle_incoming_client, std::future::pending()).await
}

/// Runs the QUIC server like [`run_quic_server`] until `shutdown` completes.
///
/// On shutdown, all connections are closed, so clients notice right away.
#[cfg_attr(
    not(coverage),
    tracing::instrument(skip(config, handle_incoming_client, shutdown))
)]
pub async fn run_quic_server_until<F, Fut, AppDataType>(
    config: ServerConfig<AppDataType>,
    handle_incoming_client: F,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()>
where
    F: Fn(Arc<ServerConfig<AppDataType>>, quinn::Connection) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), Error>> + Send + 'static,
{
    info!("Starting PR QUIC server setup");

    // Load or generate certificate.
    let (cert_chain, key_der) = load_or_generate_quic_cert(
        config.cert_hostname.clone(),
        config.key_file.clone(),
        config.cert_file.clone(),
    )
    .context("loading or generating cert")?;

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
    let mut last_limit_warning: Option<Instant> = None;
    info!("QUIC server is ready and accepting connections");
    tokio::pin!(shutdown);
    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
            () = &mut shutdown => {
                info!("Shutting down, closing all connections");
                endpoint.close(CloseCode::Ok.code(), b"server shutting down");
                let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, endpoint.wait_idle()).await;
                break;
            }
        };
        let remote = incoming.remote_address();

        if config.admission.is_blocked(remote.ip()) {
            // Refusing is cheap, it happens before the TLS handshake.
            debug!("Refusing connection from {}: address is blocked", remote);
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
                incoming.refuse();
                continue;
            };

            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(e) => {
                    config.admission.record_failure(remote.ip());
                    warn!(
                        "Failed to accept incoming QUIC connection from {}: {}",
                        remote, e
                    );
                    continue;
                }
            };

            debug!(peer = %remote, "Accepting new QUIC client connection at {:?}", start.elapsed());

            let fut = handle_incoming_client(Arc::clone(&config), connection);
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    warn!("Incoming connection dropped: {:#}", e)
                }
                // The connection no longer counts for its address.
                drop(address_slot);
            });
        }
    }

    info!("PR QUIC server terminated after {:?}.", start.elapsed());

    Ok(())
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
