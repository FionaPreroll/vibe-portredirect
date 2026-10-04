// PortRedirect Common Client Code
//
// License: GPL-3.0-only
// Based on: Quinn example code (originally licensed under Apache-2.0/MIT)
// Original: https://github.com/quinn-rs/quinn/blob/204b14792b5e92eb2c43cdb1ff05426412ff4466/quinn/examples/client.rs

use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use std::{fmt, fs, io, path::PathBuf, sync::Arc, time::Instant};
use tracing::{debug, info};

use super::fingerprint::{CertFingerprint, FingerprintVerifier};
use super::{bind_udp_socket, new_endpoint, udp_socket};
use super::{client_transport_config, CongestionControl, ALPN_QUIC_PORTREDIRECT};
use crate::host_port::{unbracketed, HostPort};
use crate::net::is_any_ipv6;
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

    /// Where to send to the server from.
    pub local: LocalAddress,
    /// The server. A name is looked up for each connection attempt.
    pub remote: HostPort,
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
        local: impl Into<LocalAddress>,
        remote: impl Into<HostPort>,
        remote_hostname_match: Option<String>,
        connection_limit: Option<usize>,
        app_data: AppDataType,
    ) -> Self {
        ClientConfig {
            remote_hostname_match,
            cert_file: config_dir.join("cert.der"),
            cert_fingerprints: Vec::new(),
            local: local.into(),
            remote: remote.into(),
            connection_limit,
            congestion_control: CongestionControl::default(),
            shutdown: Shutdown::default(),
            app_data,
        }
    }
}

/// The local address a client sends to the server from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAddress {
    /// Any address, of IPv6 and IPv4, or only of IPv4 on a system without IPv6, and `port`, 0 for
    /// any. The client connects to the server's IPv4 address, if it has one.
    Any { port: u16 },
    /// The address. The client connects to the server's address of its family, from `::` also
    /// to an IPv4 address if the server has no IPv6 one.
    Address(SocketAddr),
}

impl From<SocketAddr> for LocalAddress {
    fn from(address: SocketAddr) -> Self {
        LocalAddress::Address(address)
    }
}

impl fmt::Display for LocalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocalAddress::Any { port: 0 } => write!(f, "any address"),
            LocalAddress::Any { port } => write!(f, "any address, port {}", port),
            LocalAddress::Address(address) => write!(f, "{}", address),
        }
    }
}

impl LocalAddress {
    /// Binds a UDP socket to the address. Returns it with the server's addresses it reaches.
    fn bind(self) -> io::Result<(std::net::UdpSocket, Reach)> {
        let (socket, address) = match self {
            LocalAddress::Any { port } => any_address(dual_stack_socket(), port)?,
            LocalAddress::Address(address) => (udp_socket(address)?, address),
        };
        let prefer_ipv4 = matches!(self, LocalAddress::Any { .. });
        let reach = Reach::of(&socket, address, prefer_ipv4);
        let buffer_size = PortRedirectProtocol::UDP_SOCKET_BUFFER_SIZE;
        Ok((bind_udp_socket(socket, address, buffer_size)?, reach))
    }
}

/// Returns an IPv6 socket that sends to IPv4 addresses, too, if the system supports that.
fn dual_stack_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    Ok(socket)
}

/// Returns the socket for any address and `port`, and the address to bind it to: `dual_stack`
/// on `::`, or, if the system has no such socket, an IPv4 socket on `0.0.0.0`.
fn any_address(dual_stack: io::Result<Socket>, port: u16) -> io::Result<(Socket, SocketAddr)> {
    match dual_stack {
        Ok(socket) => Ok((socket, SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))),
        Err(e) => {
            info!(
                "Connecting over IPv4 only, as the system has no socket for both IPv6 and IPv4: {}",
                e
            );
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            Ok((socket, SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))))
        }
    }
}

/// The server's addresses a client's socket reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// IPv4 addresses, from an IPv4 socket.
    Ipv4,
    /// IPv6 addresses, from an IPv6 socket that doesn't send to IPv4 addresses.
    Ipv6,
    /// Both, from a socket on `::` that sends to IPv4 addresses, too. The client prefers IPv4
    /// addresses, or IPv6 ones.
    Both { prefer_ipv4: bool },
}

impl Reach {
    /// Returns the server's addresses that `socket`, about to be bound to `address`, reaches. If
    /// it reaches both families, the client prefers IPv4 addresses with `prefer_ipv4`.
    fn of(socket: &Socket, address: SocketAddr, prefer_ipv4: bool) -> Self {
        match address.ip() {
            IpAddr::V4(_) => Reach::Ipv4,
            ip if is_any_ipv6(ip) && socket.only_v6().is_ok_and(|only| !only) => {
                Reach::Both { prefer_ipv4 }
            }
            IpAddr::V6(_) => Reach::Ipv6,
        }
    }

    /// Returns the first of the server's `addresses` of the preferred family, else the first of
    /// the other family if the socket reaches it, if any.
    fn choose(self, addresses: &[SocketAddr]) -> Option<SocketAddr> {
        let first = |ipv4: bool| addresses.iter().copied().find(|a| a.is_ipv4() == ipv4);
        match self {
            Reach::Ipv4 => first(true),
            Reach::Ipv6 => first(false),
            Reach::Both { prefer_ipv4 } => first(prefer_ipv4).or_else(|| first(!prefer_ipv4)),
        }
    }
}

impl fmt::Display for Reach {
    /// Writes the families, e.g. `IPv4`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reach::Ipv4 => write!(f, "IPv4"),
            Reach::Ipv6 => write!(f, "IPv6"),
            Reach::Both { .. } => write!(f, "IPv4 or IPv6"),
        }
    }
}

/// A QUIC client endpoint, which can connect to the server repeatedly.
pub struct QuicClient<AppDataType> {
    config: Arc<ClientConfig<AppDataType>>,
    endpoint: quinn::Endpoint,
    /// The address the endpoint is bound to.
    local: SocketAddr,
    /// The server's addresses the endpoint reaches.
    reach: Reach,
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

        let (socket, reach) = config
            .local
            .bind()
            .with_context(|| format!("failed to bind {}", config.local))?;
        let local = socket.local_addr()?;
        debug!(
            "Sending to the server from {}, reaching {} addresses",
            local, reach
        );
        let mut endpoint = new_endpoint(socket, None)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            config: Arc::new(config),
            endpoint,
            local,
            reach,
        })
    }

    pub fn config(&self) -> &Arc<ClientConfig<AppDataType>> {
        &self.config
    }

    /// Connects to the server, or rather: establishes the tunnel's QUIC connection.
    ///
    /// Looks up the server's name first, see [`QuicClient::server_address`]. The server's
    /// certificate must be issued for the name in `remote_hostname_match`, or else for the
    /// address.
    pub async fn connect(&self) -> Result<quinn::Connection> {
        let start = Instant::now();
        let remote = self.server_address().await?;
        let server_name = match &self.config.remote_hostname_match {
            Some(name) => unbracketed(name).to_string(),
            None => remote.ip().to_string(),
        };
        info!(
            server_name_match = server_name,
            local = self.local.to_string(),
            remote = remote.to_string(),
            "Connecting to PR QUIC Server"
        );
        let connection = self
            .endpoint
            .connect(remote, &server_name)?
            .await
            .context("failed to connect")?;
        info!("PR QUIC connection established in {:?}.", start.elapsed());
        Ok(connection)
    }

    /// Looks up the server's addresses, and returns the one to connect to, see
    /// [`LocalAddress`].
    async fn server_address(&self) -> Result<SocketAddr> {
        let remote = &self.config.remote;
        let addresses = remote
            .lookup()
            .await
            .with_context(|| format!("failed to look up the server {}", remote))?;
        self.reach.choose(&addresses).with_context(|| {
            format!(
                "the server {} has no {} address, the only kind the client reaches from {}",
                remote, self.reach, self.local
            )
        })
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

    use crate::tests::ipv6_available;

    #[test]
    fn test_client_connects_to_an_address_of_the_server_it_reaches() {
        let [v4, v6]: [SocketAddr; 2] =
            ["127.0.0.1:4433", "[::1]:4433"].map(|a| a.parse().unwrap());
        let ipv4_first = Reach::Both { prefer_ipv4: true };
        let ipv6_first = Reach::Both { prefer_ipv4: false };
        // E.g. localhost, IPv6 first.
        assert_eq!(ipv4_first.choose(&[v6, v4]), Some(v4));
        assert_eq!(ipv6_first.choose(&[v4, v6]), Some(v6));
        assert_eq!(Reach::Ipv4.choose(&[v6, v4]), Some(v4));
        assert_eq!(Reach::Ipv6.choose(&[v4, v6]), Some(v6));
        // Without one of the preferred family, one of the other, if the socket reaches it.
        assert_eq!(ipv4_first.choose(&[v6]), Some(v6));
        assert_eq!(ipv6_first.choose(&[v4]), Some(v4));
        assert_eq!(Reach::Ipv4.choose(&[v6]), None);
        assert_eq!(Reach::Ipv6.choose(&[v4]), None);
        assert_eq!(ipv4_first.choose(&[]), None);
        // As error messages name them.
        let written = [Reach::Ipv4, Reach::Ipv6, ipv4_first].map(|reach| reach.to_string());
        assert_eq!(written, ["IPv4", "IPv6", "IPv4 or IPv6"]);
    }

    #[test]
    fn test_local_addresses_reach_server_addresses_of_their_family() -> io::Result<()> {
        // Any address: of both families, preferring IPv4, or only of IPv4 without IPv6.
        let (socket, reach) = LocalAddress::Any { port: 0 }.bind()?;
        let ipv6 = ipv6_available();
        let both = (
            IpAddr::from(Ipv6Addr::UNSPECIFIED),
            Reach::Both { prefer_ipv4: true },
        );
        let ipv4 = (IpAddr::from(Ipv4Addr::UNSPECIFIED), Reach::Ipv4);
        let expected = if ipv6 { both } else { ipv4 };
        assert_eq!((socket.local_addr()?.ip(), reach), expected);
        assert_ne!(socket.local_addr()?.port(), 0);

        let reach_from = |ip: IpAddr| -> io::Result<Reach> {
            Ok(LocalAddress::from(SocketAddr::new(ip, 0)).bind()?.1)
        };
        assert_eq!(reach_from(Ipv4Addr::UNSPECIFIED.into())?, Reach::Ipv4);
        if ipv6 {
            let ipv6_first = Reach::Both { prefer_ipv4: false };
            assert_eq!(reach_from(Ipv6Addr::UNSPECIFIED.into())?, ipv6_first);
            assert_eq!(reach_from(Ipv6Addr::LOCALHOST.into())?, Reach::Ipv6);
        }
        Ok(())
    }

    #[test]
    fn test_without_ipv6_any_address_is_one_of_ipv4() -> io::Result<()> {
        let no_ipv6 = Err(io::Error::from(io::ErrorKind::Unsupported));
        let (socket, address) = any_address(no_ipv6, 4434)?;
        assert_eq!(address, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4434)));
        assert_eq!(socket.domain()?, Domain::IPV4);
        Ok(())
    }

    #[test]
    fn test_local_addresses_are_written_for_the_log() {
        assert_eq!(LocalAddress::Any { port: 0 }.to_string(), "any address");
        let any_with_port = LocalAddress::Any { port: 4434 };
        assert_eq!(any_with_port.to_string(), "any address, port 4434");
        let address = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 4434));
        assert_eq!(LocalAddress::from(address).to_string(), "[::]:4434");
    }

    /// Presents the same certificate to every client, and signs with a key that may not belong
    /// to it.
    #[derive(Debug)]
    struct FixedCertificate(Arc<CertifiedKey>);

    impl ResolvesServerCert for FixedCertificate {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    /// Returns a QUIC server endpoint on `address` that presents `certificate` and signs with
    /// `key`.
    fn server_endpoint(
        address: SocketAddr,
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
        Ok(quinn::Endpoint::server(config, address)?)
    }

    /// Connects to a server that presents `certificate` and signs with `key`, see
    /// [`connect_to`].
    async fn connect(
        certificate: &rcgen::CertifiedKey<rcgen::KeyPair>,
        key: &rcgen::KeyPair,
        fingerprints: Vec<CertFingerprint>,
    ) -> Result<()> {
        let localhost = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let server = server_endpoint(localhost, certificate, key)?;
        connect_to(&server, localhost.into(), fingerprints).await
    }

    /// Connects from `local` to `server`. The client trusts certificates with `fingerprints`,
    /// has no copy of the certificate and expects a name the certificate isn't issued for.
    async fn connect_to(
        server: &quinn::Endpoint,
        local: LocalAddress,
        fingerprints: Vec<CertFingerprint>,
    ) -> Result<()> {
        let empty_dir = tempfile::tempdir()?;
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
    async fn test_client_on_any_address_reaches_servers_over_ipv4_and_ipv6() -> Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = generate();
        let fingerprint = CertFingerprint::of(server.cert.der());
        let mut addresses = vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))];
        if ipv6_available() {
            addresses.push(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)));
        }
        for address in addresses {
            let endpoint = server_endpoint(address, &server, &server.signing_key)?;
            let any = LocalAddress::Any { port: 0 };
            connect_to(&endpoint, any, vec![fingerprint]).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_client_explains_server_addresses_it_cant_reach() -> Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let server = SocketAddr::from((Ipv6Addr::LOCALHOST, 4433));
        let mut config =
            ClientConfig::create_default_config(PathBuf::new(), local, server, None, None, ());
        config.cert_fingerprints = vec![CertFingerprint::of(b"any certificate")];
        let client = QuicClient::new(config)?;

        let err = format!("{:#}", client.connect().await.unwrap_err());
        let expected = format!(
            "the server [::1]:4433 has no IPv4 address, the only kind the client reaches from {}",
            client.local
        );
        assert_eq!(err, expected);
        Ok(())
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
