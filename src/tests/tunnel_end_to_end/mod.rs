// End-to-End Tests of a complete PortRedirect tunnel.
//
// Unlike the minimal QUIC tests, these run the real server and client connection handlers:
// authentication, control channel, TCP listener and data forwarding.

mod authentication;
mod forwarding;
mod limits;
mod protocol;
mod reconnect_and_reload;
mod shutdown;

use anyhow::{anyhow, Result};
use secrecy::SecretString;
use std::future::Future;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, timeout_at, Duration, Instant};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::subscriber::DefaultGuard;

use crate::app_data::{ClientAppData, ServerAppData};
use crate::bi_stream::BiStream;
use crate::client::reconnect::{Backoff, REFUSED_HINT};
use crate::client::run_client::{run_client, ClientSettings};
use crate::client::server_handler::handle_quic_server_connection;
use crate::forward::forward_tcp_and_quic;
use crate::host_port::HostPort;
use crate::limits::{BlockingPolicy, QuicAdmission};
use crate::metrics::DummyCounter;
use crate::protocol::auth::{client_authenticate, session_binding, ClientName};
use crate::protocol::close::CloseCode;
use crate::protocol::control::{receive_hello, send_welcome, SERVER_SOFTWARE};
use crate::protocol::control::{request_listen_port, Greeting, CLIENT_SOFTWARE};
use crate::protocol::message::{read_message, write_message, Message, MessageType};
use crate::quic::client::{run_quic_client, ClientConfig, LocalAddress, QuicClient};
use crate::quic::fingerprint::CertFingerprint;
use crate::quic::server::{
    load_or_generate_quic_cert, raise_receive_window, run_quic_server, ServerConfig,
};
use crate::quic::CongestionControl;
use crate::server::auth::authenticate_quic_client;
use crate::server::client_handler::{handle_quic_client_connection, serve_client};
use crate::server::clients::{ClientEntry, ClientList};
use crate::server::metrics::{ClientMetrics, METRICS};
use crate::server::reload::Settings;
use crate::server::{ForwardingLimits, PortSpec};
use crate::shutdown::Shutdown;
use crate::tests::{capture_logs, collect_logs, ipv6_available, CollectedLogs};
use crate::tests::{free_tcp_port, free_udp_port};
use crate::PortRedirectProtocol;

const TEST_PSK: &str = "integration-test-psk";
const CERT_HOSTNAME: &str = "localhost";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn ipv6_localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv6Addr::LOCALHOST, port))
}

/// Deterministic test data, different for each seed.
fn test_pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 8) as u8)
        .collect()
}

/// Runs a test body with a global timeout, so a broken tunnel fails the test instead of hanging.
async fn with_timeout<F: Future<Output = Result<()>>>(test: F) -> Result<()> {
    timeout(TEST_TIMEOUT, test)
        .await
        .map_err(|_| anyhow!("test timed out after {:?}", TEST_TIMEOUT))?
}

/// Prepares a test: its log messages go to its output, shown if it fails, and its configuration
/// directory holds the server's certificate. Keep both until the test ends.
fn setup() -> (tempfile::TempDir, DefaultGuard) {
    let logs = capture_logs();
    // Several tests run in this process, only the first installation succeeds.
    let _ = rustls::crypto::ring::default_provider().install_default();
    (certificate_dir(), logs)
}

/// Returns a configuration directory with a new server certificate. It is generated up front, so
/// the client finds it when it starts.
fn certificate_dir() -> tempfile::TempDir {
    let config_dir = tempfile::tempdir().expect("failed to create temp dir");
    load_or_generate_quic_cert(
        CERT_HOSTNAME.into(),
        config_dir.path().join("key.der"),
        config_dir.path().join("cert.der"),
    )
    .expect("failed to generate certificate");
    config_dir
}

/// Starts a TCP echo server standing in for the backend service behind the client.
/// Each connection is echoed until the peer closes its sending side, then closed.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind(localhost(0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_echo(listener));
    addr
}

/// Echoes each connection accepted by `listener`, see [`start_echo_server`].
async fn serve_echo(listener: TcpListener) {
    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let (mut read, mut write) = stream.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
            let _ = write.shutdown().await;
        });
    }
}

/// Starts a backend service that reads each connection to its end and only then answers, with
/// the received data reversed, like a server that needs the whole request.
async fn start_reversing_server() -> SocketAddr {
    let listener = TcpListener::bind(localhost(0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await?;
                request.reverse();
                stream.write_all(&request).await?;
                stream.shutdown().await
            });
        }
    });
    addr
}

fn start_server(config_dir: &Path, quic_port: u16, allowed_ports: Vec<PortSpec>) -> JoinHandle<()> {
    start_server_with_limits(
        config_dir,
        quic_port,
        allowed_ports,
        ForwardingLimits::default(),
    )
}

fn server_config(
    config_dir: &Path,
    quic_port: u16,
    allowed_ports: Vec<PortSpec>,
    limits: ForwardingLimits,
) -> ServerConfig<ServerAppData> {
    let quic = localhost(quic_port);
    server_config_on(config_dir, quic, "127.0.0.1", allowed_ports, limits)
}

/// Like [`server_config`], for a server that listens on `quic` for QUIC connections and on
/// `listen_host` for external ones.
fn server_config_on(
    config_dir: &Path,
    quic: SocketAddr,
    listen_host: &str,
    allowed_ports: Vec<PortSpec>,
    limits: ForwardingLimits,
) -> ServerConfig<ServerAppData> {
    let app_data = ServerAppData::new(TEST_PSK.into(), listen_host.into(), allowed_ports)
        .with_forwarding_limits(limits);
    ServerConfig::create_default_config(
        config_dir.to_path_buf(),
        CERT_HOSTNAME.into(),
        quic,
        None,
        app_data,
    )
}

/// Returns the configuration of a server that accepts `clients`, each given as name, PSKs and
/// allowed port.
fn server_config_with_clients(
    config_dir: &Path,
    quic_port: u16,
    clients: &[(&str, &[&str], u16)],
) -> ServerConfig<ServerAppData> {
    let clients = ClientList::new(clients.iter().map(|&(name, psks, port)| ClientEntry {
        name: name.parse().unwrap(),
        psks: psks.iter().map(|&psk| psk.into()).collect(),
        ports: vec![PortSpec::Single(port)],
    }))
    .expect("invalid client list");
    ServerConfig::create_default_config(
        config_dir.to_path_buf(),
        CERT_HOSTNAME.into(),
        localhost(quic_port),
        None,
        ServerAppData::with_clients(clients, "127.0.0.1".into()),
    )
}

fn start_server_with_limits(
    config_dir: &Path,
    quic_port: u16,
    allowed_ports: Vec<PortSpec>,
    limits: ForwardingLimits,
) -> JoinHandle<()> {
    let config = server_config(config_dir, quic_port, allowed_ports, limits);
    spawn_server_with_handler(config, handle_quic_client_connection)
}

/// Runs a server that hands each connection to `handler`, e.g. instead of the real connection
/// handler to test the client against a misbehaving server.
fn spawn_server_with_handler<F, Fut>(
    config: ServerConfig<ServerAppData>,
    handler: F,
) -> JoinHandle<()>
where
    F: Fn(Arc<ServerConfig<ServerAppData>>, quinn::Connection) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        run_quic_server(config, handler)
            .await
            .expect("server failed");
    })
}

/// Starts a server that shuts down when `shutdown` asks it to.
/// Retries for a while if the port is still in use, e.g. by a previous server.
fn start_server_until(
    config_dir: &Path,
    quic_port: u16,
    allowed_ports: Vec<PortSpec>,
    shutdown: Shutdown,
) -> JoinHandle<Result<()>> {
    let config_dir = config_dir.to_path_buf();
    tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(5);
        // Bind a socket first, so a busy port doesn't consume the shutdown signal.
        while std::net::UdpSocket::bind(localhost(quic_port)).is_err() {
            anyhow::ensure!(Instant::now() < deadline, "QUIC port stays in use");
            sleep(Duration::from_millis(50)).await;
        }
        let mut config = server_config(
            &config_dir,
            quic_port,
            allowed_ports,
            ForwardingLimits::default(),
        );
        config.shutdown = shutdown;
        run_quic_server(config, handle_quic_client_connection).await
    })
}

/// A client running `run_client` in the background, like `portredirect_client`.
struct TestClient {
    task: JoinHandle<Result<()>>,
    shutdown: Shutdown,
}

impl TestClient {
    /// Waits until the client stops by itself, i.e. after a permanent error, or after a shutdown.
    async fn result(self) -> Result<()> {
        self.task.await?
    }

    /// Shuts the client down, like a SIGTERM does.
    async fn stop(self) -> Result<()> {
        self.shutdown.drain();
        self.task.await?
    }
}

/// Returns the settings of a client with short reconnection delays.
fn client_settings(
    config_dir: &Path,
    quic_port: u16,
    psk: &str,
    destination: SocketAddr,
    remote_listen_port: u16,
) -> ClientSettings {
    ClientSettings {
        app_data: ClientAppData::new(psk.into(), destination, remote_listen_port),
        config_dir: config_dir.to_path_buf(),
        quic_local: localhost(0).into(),
        quic_remote: localhost(quic_port).into(),
        quic_cert_hostname: Some(CERT_HOSTNAME.into()),
        cert_fingerprints: Vec::new(),
        max_connections: PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS,
        congestion_control: CongestionControl::default(),
        metrics_addr: None,
        reconnect_backoff: Backoff::new(Duration::from_millis(100), Duration::from_secs(1)),
        shutdown: Shutdown::default(),
    }
}

/// Starts a client with short reconnection delays.
fn start_client(
    config_dir: &Path,
    quic_port: u16,
    psk: &str,
    destination: SocketAddr,
    remote_listen_port: u16,
) -> TestClient {
    spawn_client(client_settings(
        config_dir,
        quic_port,
        psk,
        destination,
        remote_listen_port,
    ))
}

/// Starts a client named `name` with short reconnection delays.
fn start_named_client(
    config_dir: &Path,
    quic_port: u16,
    name: &str,
    psk: &str,
    destination: SocketAddr,
    remote_listen_port: u16,
) -> TestClient {
    let mut settings = client_settings(config_dir, quic_port, psk, destination, remote_listen_port);
    settings.app_data = settings.app_data.with_client_name(name.parse().unwrap());
    spawn_client(settings)
}

/// Runs a client with `settings` in the background.
fn spawn_client(settings: ClientSettings) -> TestClient {
    let shutdown = settings.shutdown.clone();
    let task = tokio::spawn(run_client(settings));
    TestClient { task, shutdown }
}

/// Makes one connection attempt with the real client handler and returns the error if the
/// connection could not be established.
async fn connect_once(
    config_dir: &Path,
    quic_port: u16,
    psk: &str,
    remote_listen_port: u16,
) -> std::result::Result<(), String> {
    let app_data = ClientAppData::new(psk.into(), localhost(1), remote_listen_port);
    let config = ClientConfig::create_default_config(
        config_dir.to_path_buf(),
        localhost(0),
        localhost(quic_port),
        Some(CERT_HOSTNAME.into()),
        None,
        app_data,
    );
    run_quic_client(config, handle_quic_server_connection)
        .await
        .map_err(|e| format!("{:#}", e))
}

/// The control stream of a connection, as the client sees it.
type ControlStream = BiStream<Compat<quinn::RecvStream>, Compat<quinn::SendStream>>;

/// Connects to the server without running the client's connection handler, so a test can speak
/// the protocol itself. The connection uses the client's endpoint, so keep the returned client.
async fn connect_raw(
    config_dir: &Path,
    quic_port: u16,
) -> Result<(QuicClient<ClientAppData>, quinn::Connection)> {
    connect_raw_from(config_dir, quic_port, Ipv4Addr::LOCALHOST).await
}

/// Like [`connect_raw`], from the local address `source`.
async fn connect_raw_from(
    config_dir: &Path,
    quic_port: u16,
    source: Ipv4Addr,
) -> Result<(QuicClient<ClientAppData>, quinn::Connection)> {
    let config = ClientConfig::create_default_config(
        config_dir.to_path_buf(),
        SocketAddr::from((source, 0)),
        localhost(quic_port),
        Some(CERT_HOSTNAME.into()),
        None,
        ClientAppData::new(TEST_PSK.into(), localhost(1), 1),
    );
    let client = QuicClient::new(config)?;
    let connection = client.connect().await?;
    Ok((client, connection))
}

/// Returns whether the server refused a connection, e.g. because of a limit.
fn refused<T>(result: &Result<T>) -> bool {
    result
        .as_ref()
        .is_err_and(|e| format!("{:#}", e).contains("refused"))
}

/// Accepts the control stream of a raw connection and authenticates as the default client with
/// the test PSK.
async fn authenticated_control_stream(connection: &quinn::Connection) -> Result<ControlStream> {
    authenticated_control_stream_as(connection, ClientName::DEFAULT, TEST_PSK).await
}

/// Like [`authenticated_control_stream`], as the client `name` with `psk`.
async fn authenticated_control_stream_as(
    connection: &quinn::Connection,
    name: &str,
    psk: &str,
) -> Result<ControlStream> {
    let (send, recv) = connection.accept_bi().await?;
    let mut control_stream = BiStream::new(recv.compat(), send.compat_write(), "control".into());
    client_authenticate(
        &mut control_stream,
        &name.parse().map_err(|e: String| anyhow!(e))?,
        &SecretString::from(psk),
        &session_binding(connection)?,
    )
    .await?;
    Ok(control_stream)
}

/// Asks the server to listen on `port` and returns the port it listens on.
async fn request_port(control_stream: &mut ControlStream, port: u16) -> Result<u16> {
    let hello = Greeting::new(CLIENT_SOFTWARE, port);
    Ok(request_listen_port(control_stream, &hello)
        .await?
        .listen_port)
}

/// Waits until the server no longer accepts connections on `port`.
async fn wait_until_closed(port: u16) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(localhost(port)).await.is_ok() {
        anyhow::ensure!(Instant::now() < deadline, "port {} is still open", port);
        sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

/// Connects to the server's external TCP port, retrying until the tunnel is up.
async fn connect_through_tunnel(port: u16) -> Result<TcpStream> {
    connect_through_tunnel_at(localhost(port)).await
}

/// Like [`connect_through_tunnel`], to the server's `address`.
async fn connect_through_tunnel_at(address: SocketAddr) -> Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(e) if Instant::now() > deadline => {
                return Err(anyhow!("tunnel did not come up on {}: {}", address, e))
            }
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
}

/// Sends `message` through the tunnel until it comes back, e.g. while the client reconnects.
async fn echo_once_the_tunnel_is_back(port: u16, message: &[u8]) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let attempt = async {
            let stream = connect_through_tunnel(port).await?;
            echo_roundtrip(stream, message.to_vec()).await
        };
        if let Ok(Ok(echoed)) = timeout(Duration::from_secs(2), attempt).await {
            if echoed == message {
                return Ok(());
            }
        }
        anyhow::ensure!(Instant::now() < deadline, "tunnel did not come back");
        sleep(Duration::from_millis(100)).await;
    }
}

/// Returns the fingerprint of the server certificate in `config_dir`.
fn fingerprint_of(config_dir: &tempfile::TempDir) -> Result<CertFingerprint> {
    let certificate = std::fs::read(config_dir.path().join("cert.der"))?;
    Ok(CertFingerprint::of(&certificate))
}

/// Connects to the server's external TCP port from the local address `source`.
///
/// On Linux, all of 127.0.0.0/8 is local, which lets tests act as different hosts.
async fn connect_from(source: Ipv4Addr, port: u16) -> std::io::Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from((source, 0)))?;
    socket.connect(localhost(port)).await
}

/// Sends `message` through an echoing tunnel connection and checks that it comes back.
async fn echo_once(stream: &mut TcpStream, message: &[u8]) -> Result<()> {
    stream.write_all(message).await?;
    let mut echoed = vec![0u8; message.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .map_err(|_| anyhow!("no echo within 5 seconds"))??;
    anyhow::ensure!(echoed == message, "echo differs from message");
    Ok(())
}

/// Returns whether the peer closed the connection within `within`, without sending data.
async fn closed_by_peer(stream: &mut TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 16];
    match timeout(within, stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(_)) => panic!("unexpected data from an idle connection"),
        Err(_) => false,
    }
}

/// How a TCP connection ended, as seen from one end.
#[derive(Debug, PartialEq, Eq)]
enum TcpEnd {
    /// The peer closed the connection normally (FIN).
    Normal,
    /// The peer reset the connection (RST).
    Reset,
    /// The connection is still open.
    Open,
}

/// Reads from `stream`, discarding the data, until it ends or `within` passed.
async fn tcp_end(stream: &mut TcpStream, within: Duration) -> TcpEnd {
    let deadline = Instant::now() + within;
    let mut buf = [0u8; 1024];
    loop {
        match timeout_at(deadline, stream.read(&mut buf)).await {
            Err(_) => return TcpEnd::Open,
            Ok(Ok(0)) => return TcpEnd::Normal,
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == ErrorKind::ConnectionReset => return TcpEnd::Reset,
            Ok(Err(e)) => panic!("unexpected error reading from a TCP connection: {}", e),
        }
    }
}

/// Starts a backend service that hands each accepted connection to the test.
async fn start_accepting_server() -> (SocketAddr, mpsc::UnboundedReceiver<TcpStream>) {
    let listener = TcpListener::bind(localhost(0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            if accepted.send(stream).is_err() {
                break;
            }
        }
    });
    (addr, receiver)
}

/// Sends `payload`, closes the sending side and returns everything received until EOF.
async fn echo_roundtrip(stream: TcpStream, payload: Vec<u8>) -> Result<Vec<u8>> {
    let (mut read, mut write) = stream.into_split();
    // Write concurrently to reading, otherwise both directions' buffers can fill up and block.
    let writer = tokio::spawn(async move {
        write.write_all(&payload).await?;
        write.shutdown().await
    });

    let mut received = Vec::new();
    read.read_to_end(&mut received).await?;
    writer.await??;
    Ok(received)
}

/// Writes to `send` until a write doesn't go through within a moment, or `limit` bytes are
/// written. Returns how many bytes were written.
async fn write_until_blocked<W: AsyncWrite + Unpin>(send: &mut W, limit: usize) -> Result<usize> {
    let chunk = [0u8; 4096];
    let mut written = 0;
    while written < limit {
        let end = chunk.len().min(limit - written);
        match timeout(Duration::from_millis(300), send.write(&chunk[..end])).await {
            Ok(result) => written += result?,
            Err(_) => break,
        }
    }
    Ok(written)
}

/// Waits for `task` to end, for at most 10 seconds.
async fn ended<T>(task: impl Future<Output = T>, what: &str) -> Result<T> {
    timeout(Duration::from_secs(10), task)
        .await
        .map_err(|_| anyhow!("{} did not end", what))
}

/// Waits until `value` returns `expected`.
async fn wait_for_metric(value: impl Fn() -> i64, expected: i64, what: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while value() != expected {
        anyhow::ensure!(
            Instant::now() < deadline,
            "{} is {}, not {}",
            what,
            value(),
            expected
        );
        sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

/// Waits until `log` has `count` lines, and returns them.
async fn wait_for_lines(log: &CollectedLogs, count: usize) -> Vec<String> {
    loop {
        let lines = log.lines();
        if lines.len() >= count {
            return lines;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

/// Returns the settings of a server that accepts `clients`, each given as name, PSKs and allowed
/// port, like [`server_config_with_clients`].
fn settings_with_clients(clients: &[(&str, &[&str], u16)]) -> Result<Settings> {
    let clients = ClientList::new(clients.iter().map(|&(name, psks, port)| ClientEntry {
        name: name.parse().unwrap(),
        psks: psks.iter().map(|&psk| psk.into()).collect(),
        ports: vec![PortSpec::Single(port)],
    }))?;
    Ok(Settings {
        clients,
        forwarding_limits: ForwardingLimits::default(),
    })
}

/// Returns how many tunnels the server set up for the client `name` so far.
fn tunnels_of(name: &str) -> u64 {
    METRICS.client(&name.parse().unwrap()).tunnels.get()
}

/// The reading half of a control stream, which reports, when the stream ends, whether its
/// connection was closed before.
struct EndWatch {
    read: Compat<quinn::RecvStream>,
    connection: quinn::Connection,
    closed_before: mpsc::UnboundedSender<bool>,
}

impl AsyncRead for EndWatch {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl Drop for EndWatch {
    fn drop(&mut self) {
        let closed = self.connection.close_reason().is_some();
        let _ = self.closed_before.send(closed);
    }
}

/// A client that stops in the middle of the TLS handshake: it doesn't send its Finished, because
/// verifying the server's certificate takes until the test releases it.
struct StalledHandshake {
    release: std::sync::mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl StalledHandshake {
    /// Starts the handshake and returns once the server waits for the client's Finished.
    async fn start(quic_port: u16) -> Result<Self> {
        let (entered, entered_rx) = oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        // The verifier blocks its thread, so the client gets a runtime of its own.
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let verifier = StallingVerifier {
                    entered: std::sync::Mutex::new(Some(entered)),
                    release: std::sync::Mutex::new(release_rx),
                };
                let mut crypto = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_no_client_auth();
                crypto.alpn_protocols = vec![b"pr-5".to_vec()];
                let mut endpoint = quinn::Endpoint::client(localhost(0)).unwrap();
                endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
                    quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
                )));
                let result = endpoint
                    .connect(localhost(quic_port), CERT_HOSTNAME)
                    .unwrap()
                    .await;
                assert!(result.is_err(), "the stalled handshake succeeded");
            });
        });
        timeout(Duration::from_secs(10), entered_rx)
            .await
            .map_err(|_| anyhow!("the handshake did not get to the server's certificate"))??;
        Ok(Self { release, thread })
    }

    /// Lets the client go on, which then fails the handshake.
    async fn release(self) -> Result<()> {
        let _ = self.release.send(());
        tokio::task::spawn_blocking(move || self.thread.join())
            .await?
            .map_err(|_| anyhow!("the stalled client panicked"))
    }
}

/// A certificate verifier that waits until it is released, and then rejects the certificate.
#[derive(Debug)]
struct StallingVerifier {
    entered: std::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl rustls::client::danger::ServerCertVerifier for StallingVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        let _ = self
            .release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(60));
        Err(rustls::Error::General("stalled on purpose".into()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("not used".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("not used".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Keeps each connection open until the peer closes it.
async fn hold_connection(
    _config: Arc<ServerConfig<ServerAppData>>,
    connection: quinn::Connection,
) -> Result<()> {
    connection.closed().await;
    Ok(())
}
