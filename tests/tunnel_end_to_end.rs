// End-to-End Tests of a complete PortRedirect tunnel.
//
// Unlike the minimal QUIC tests, these run the real server and client connection handlers:
// authentication, control channel, TCP listener and data forwarding.

use anyhow::{anyhow, Result};
use portredirect::app_data::{ClientAppData, ServerAppData};
use portredirect::bi_stream::BiStream;
use portredirect::client::reconnect::Backoff;
use portredirect::client::run_client::{run_client, ClientSettings};
use portredirect::client::server_handler::handle_quic_server_connection;
use portredirect::forward::forward_tcp_and_quic;
use portredirect::limits::{BlockingPolicy, QuicAdmission};
use portredirect::metrics_helper::DummyCounter;
use portredirect::protocol::auth::{client_authenticate, session_binding, ClientName};
use portredirect::protocol::close::CloseCode;
use portredirect::protocol::control::{receive_hello, send_welcome, SERVER_SOFTWARE};
use portredirect::protocol::control::{request_listen_port, Greeting, CLIENT_SOFTWARE};
use portredirect::protocol::message::{read_message, write_message, Message, MessageType};
use portredirect::quic::client::{run_quic_client, ClientConfig, QuicClient};
use portredirect::quic::server::{
    load_or_generate_quic_cert, run_quic_server, run_quic_server_until, ServerConfig,
};
use portredirect::server::auth::authenticate_quic_client;
use portredirect::server::client_handler::handle_quic_client_connection;
use portredirect::server::clients::{ClientEntry, ClientList};
use portredirect::server::{ForwardingLimits, PortSpec};
use portredirect::PortRedirectProtocol;
use secrecy::SecretString;
use std::future::Future;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, timeout_at, Duration, Instant};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

const TEST_PSK: &str = "integration-test-psk";
const CERT_HOSTNAME: &str = "localhost";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Returns a TCP port that was free a moment ago.
fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind(localhost(0))
        .and_then(|l| l.local_addr())
        .expect("failed to find free TCP port")
        .port()
}

/// Returns a UDP port that was free a moment ago.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind(localhost(0))
        .and_then(|s| s.local_addr())
        .expect("failed to find free UDP port")
        .port()
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

fn setup() -> tempfile::TempDir {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    // Several tests run in this process, only the first installation succeeds.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Generate the server certificate up front, so the client finds it when it starts.
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
    let app_data = ServerAppData::new(TEST_PSK.into(), "127.0.0.1".into(), allowed_ports)
        .with_forwarding_limits(limits);
    ServerConfig::create_default_config(
        config_dir.to_path_buf(),
        CERT_HOSTNAME.into(),
        localhost(quic_port),
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

/// Starts a server that shuts down when `shutdown` receives a value or is dropped.
/// Retries for a while if the port is still in use, e.g. by a previous server.
fn start_server_until(
    config_dir: &Path,
    quic_port: u16,
    allowed_ports: Vec<PortSpec>,
    shutdown: oneshot::Receiver<()>,
) -> JoinHandle<Result<()>> {
    let config_dir = config_dir.to_path_buf();
    tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(5);
        // Bind a socket first, so a busy port doesn't consume the shutdown signal.
        while std::net::UdpSocket::bind(localhost(quic_port)).is_err() {
            anyhow::ensure!(Instant::now() < deadline, "QUIC port stays in use");
            sleep(Duration::from_millis(50)).await;
        }
        let config = server_config(
            &config_dir,
            quic_port,
            allowed_ports,
            ForwardingLimits::default(),
        );
        run_quic_server_until(config, handle_quic_client_connection, async move {
            let _ = shutdown.await;
        })
        .await
    })
}

/// A client running `run_client` in the background, like `portredirect_client`.
struct TestClient {
    task: JoinHandle<Result<()>>,
    shutdown: oneshot::Sender<()>,
}

impl TestClient {
    /// Waits until the client stops by itself, i.e. after a permanent error.
    async fn result(self) -> Result<()> {
        let TestClient { task, shutdown } = self;
        let result = task.await?;
        drop(shutdown);
        result
    }

    /// Shuts the client down, like a SIGTERM does.
    async fn stop(self) -> Result<()> {
        let _ = self.shutdown.send(());
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
        quic_local_addr: localhost(0),
        quic_remote_addr: localhost(quic_port),
        quic_remote_hostname_match: Some(CERT_HOSTNAME.into()),
        max_connections: PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS,
        metrics_addr: None,
        reconnect_backoff: Backoff::new(Duration::from_millis(100), Duration::from_secs(1)),
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
    let (shutdown, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(run_client(settings, async move {
        let _ = shutdown_rx.await;
    }));
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
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(localhost(port)).await {
            Ok(stream) => return Ok(stream),
            Err(e) if Instant::now() > deadline => {
                return Err(anyhow!("tunnel did not come up on port {}: {}", port, e))
            }
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
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

#[tokio::test]
async fn tunnel_forwards_data_in_both_directions() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        // Large enough to need flow control and many QUIC packets.
        let payload = test_pattern(4 * 1024 * 1024, 1);
        let stream = connect_through_tunnel(listen_port).await?;
        let received = echo_roundtrip(stream, payload.clone()).await?;

        assert_eq!(received.len(), payload.len(), "received length differs");
        assert!(received == payload, "received data differs from sent data");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn tunnel_handles_concurrent_connections() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Range(listen_port, listen_port)],
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        // Wait for the tunnel with a first connection, then run many in parallel.
        let first = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(first, b"hello".to_vec()).await?, b"hello");

        let mut connections = Vec::new();
        for seed in 0..20u8 {
            connections.push(tokio::spawn(async move {
                let payload = test_pattern(256 * 1024, seed);
                let stream = TcpStream::connect(localhost(listen_port)).await?;
                let received = echo_roundtrip(stream, payload.clone()).await?;
                anyhow::ensure!(
                    received == payload,
                    "connection {} received wrong data",
                    seed
                );
                Ok(())
            }));
        }
        for connection in connections {
            connection.await??;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn server_rejects_wrong_psk() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let client = start_client(
        config_dir.path(),
        quic_port,
        "wrong-psk",
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        // The client gives up, as connecting again would fail the same way.
        let error = format!("{:#}", client.result().await.unwrap_err());
        assert!(
            error.contains("authenticate"),
            "unexpected error: {}",
            error
        );

        // The server must not have opened the external port.
        assert!(TcpStream::connect(localhost(listen_port)).await.is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn server_rejects_disallowed_port() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let allowed_port = listen_port.wrapping_add(1); // any port other than the requested one
    let echo_addr = start_echo_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(allowed_port)],
    );
    let client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let error = format!("{:#}", client.result().await.unwrap_err());
        assert!(
            error.contains("port not allowed"),
            "unexpected error: {}",
            error
        );

        assert!(TcpStream::connect(localhost(listen_port)).await.is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn idle_connections_are_closed() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let limits = ForwardingLimits {
        idle_timeout: Some(Duration::from_secs(1)),
        ..ForwardingLimits::default()
    };
    let _server = start_server_with_limits(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        limits,
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let mut stream = connect_through_tunnel(listen_port).await?;

        // Transfers keep the connection open beyond the idle timeout.
        for _ in 0..4 {
            sleep(Duration::from_millis(500)).await;
            echo_once(&mut stream, b"still here").await?;
        }

        // Without transfers, the server closes it, normally: nothing was lost.
        assert_eq!(
            tcp_end(&mut stream, Duration::from_secs(5)).await,
            TcpEnd::Normal
        );
        Ok(())
    })
    .await
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn connections_per_address_are_limited() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let (busy_host, other_host) = (Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3));

    let limits = ForwardingLimits {
        max_connections_per_ip: 2,
        ..ForwardingLimits::default()
    };
    let _server = start_server_with_limits(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        limits,
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let ready = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(ready, b"ready".to_vec()).await?, b"ready");

        // Two connections from one address are forwarded, a third one is closed.
        let mut first = connect_from(busy_host, listen_port).await?;
        let mut second = connect_from(busy_host, listen_port).await?;
        echo_once(&mut first, b"first").await?;
        echo_once(&mut second, b"second").await?;
        let mut third = connect_from(busy_host, listen_port).await?;
        assert!(closed_by_peer(&mut third, Duration::from_secs(5)).await);

        // Other addresses are not affected.
        let mut other = connect_from(other_host, listen_port).await?;
        echo_once(&mut other, b"other").await?;

        // Once a connection ends, its address can connect again.
        drop(first);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut retry = connect_from(busy_host, listen_port).await?;
            if echo_once(&mut retry, b"again").await.is_ok() {
                break;
            }
            anyhow::ensure!(Instant::now() < deadline, "slot was not freed");
            sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    })
    .await
}

/// Many idle connections from one host must not block the tunnel for others.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn idle_connections_from_one_address_do_not_block_others() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let (attacker, user) = (Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3));

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let ready = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(ready, b"ready".to_vec()).await?, b"ready");

        // Open 100 connections from one address and keep them idle.
        let mut checks = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let mut stream = connect_from(attacker, listen_port).await?;
            checks.spawn(async move {
                let closed = closed_by_peer(&mut stream, Duration::from_secs(2)).await;
                (stream, closed)
            });
        }

        // Only the allowed number per address is kept open.
        let mut idle = Vec::new();
        let mut closed = 0;
        while let Some(check) = checks.join_next().await {
            let (stream, was_closed) = check?;
            closed += usize::from(was_closed);
            idle.push(stream);
        }
        assert_eq!(
            closed,
            100 - ForwardingLimits::DEFAULT_MAX_CONNECTIONS_PER_IP
        );

        // Another host still gets through.
        let stream = connect_from(user, listen_port).await?;
        assert_eq!(echo_roundtrip(stream, b"hello".to_vec()).await?, b"hello");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn repeated_authentication_failures_block_address() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let max_failures = BlockingPolicy::default().max_failures;
    let refused = |result: &std::result::Result<(), String>| {
        result.as_ref().is_err_and(|e| e.contains("refused"))
    };

    with_timeout(async {
        // Guess the PSK until the server refuses connections from this address.
        let mut failed_attempts = 0;
        while !refused(&connect_once(config_dir.path(), quic_port, "wrong-psk", listen_port).await)
        {
            failed_attempts += 1;
            anyhow::ensure!(
                failed_attempts <= max_failures + 2,
                "address not blocked after {} failed attempts",
                failed_attempts
            );
        }
        anyhow::ensure!(
            failed_attempts >= max_failures,
            "address blocked after only {} failed attempts",
            failed_attempts
        );

        // While blocked, even the right PSK doesn't get in.
        let result = connect_once(config_dir.path(), quic_port, TEST_PSK, listen_port).await;
        assert!(refused(&result), "unexpected result: {:?}", result);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_reconnects_after_server_restart() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let allowed_ports = vec![PortSpec::Single(listen_port)];

    let (stop_server, server_shutdown) = oneshot::channel();
    let server = start_server_until(
        config_dir.path(),
        quic_port,
        allowed_ports.clone(),
        server_shutdown,
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(stream, b"before".to_vec()).await?, b"before");

        // Stop the server, which closes the client's connection, and start it again.
        let _ = stop_server.send(());
        server.await??;
        let (_keep_running, server_shutdown) = oneshot::channel();
        let _server =
            start_server_until(config_dir.path(), quic_port, allowed_ports, server_shutdown);

        // The client reconnects and the tunnel works again.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let attempt = async {
                let stream = connect_through_tunnel(listen_port).await?;
                echo_roundtrip(stream, b"after".to_vec()).await
            };
            if let Ok(Ok(echoed)) = timeout(Duration::from_secs(2), attempt).await {
                if echoed == b"after" {
                    break;
                }
            }
            anyhow::ensure!(Instant::now() < deadline, "tunnel did not come back");
            sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_shuts_down_cleanly() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(stream, b"hello".to_vec()).await?, b"hello");

        timeout(Duration::from_secs(5), client.stop())
            .await
            .map_err(|_| anyhow!("client did not stop"))??;

        // The server noticed right away and released the port, so a new client can use it.
        // Otherwise, the old connection would hold it until QUIC's idle timeout of 30 seconds.
        let _client = start_client(
            config_dir.path(),
            quic_port,
            TEST_PSK,
            echo_addr,
            listen_port,
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let attempt = async {
                let stream = connect_through_tunnel(listen_port).await?;
                echo_roundtrip(stream, b"again".to_vec()).await
            };
            if let Ok(Ok(echoed)) = timeout(Duration::from_secs(1), attempt).await {
                if echoed == b"again" {
                    break;
                }
            }
            anyhow::ensure!(Instant::now() < deadline, "port was not released");
            sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn responses_after_the_end_of_the_request_are_forwarded() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let reversing_addr = start_reversing_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        reversing_addr,
        listen_port,
    );

    with_timeout(async {
        // The backend answers only after the external client closed its sending side, so the
        // tunnel must keep the other direction open.
        let payload = test_pattern(256 * 1024, 3);
        let stream = connect_through_tunnel(listen_port).await?;
        let received = echo_roundtrip(stream, payload.clone()).await?;

        let expected: Vec<u8> = payload.iter().rev().copied().collect();
        assert!(
            received == expected,
            "response differs from the expected one"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn requests_after_the_end_of_the_response_are_forwarded() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());

    // The backend sends a greeting and closes its sending side, then reads the request.
    let listener = TcpListener::bind(localhost(0)).await?;
    let backend_addr = listener.local_addr()?;
    let (request_tx, request_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        stream.write_all(b"greeting").await?;
        stream.shutdown().await?;
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await?;
        let _ = request_tx.send(request);
        Ok::<_, std::io::Error>(())
    });

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        backend_addr,
        listen_port,
    );

    with_timeout(async {
        let mut stream = connect_through_tunnel(listen_port).await?;
        let mut greeting = Vec::new();
        stream.read_to_end(&mut greeting).await?;
        assert_eq!(greeting, b"greeting");

        // The external client still sends after the backend's end of the response.
        let payload = test_pattern(256 * 1024, 4);
        stream.write_all(&payload).await?;
        stream.shutdown().await?;
        let request = timeout(Duration::from_secs(5), request_rx)
            .await
            .map_err(|_| anyhow!("the backend did not receive the request"))??;
        assert!(request == payload, "request differs from the sent data");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn destination_can_speak_first() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());

    // Like an SMTP, POP3 or FTP server: the backend greets first, and the external client sends
    // nothing before the greeting.
    let listener = TcpListener::bind(localhost(0)).await?;
    let backend_addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                stream.write_all(b"220 ready\r\n").await?;
                let mut command = [0u8; 6];
                stream.read_exact(&mut command).await?;
                anyhow::ensure!(&command == b"QUIT\r\n", "unexpected command");
                stream.write_all(b"221 bye\r\n").await?;
                stream.shutdown().await?;
                Ok(())
            });
        }
    });

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        backend_addr,
        listen_port,
    );

    with_timeout(async {
        let mut stream = connect_through_tunnel(listen_port).await?;
        let mut greeting = [0u8; 11];
        timeout(Duration::from_secs(5), stream.read_exact(&mut greeting))
            .await
            .map_err(|_| anyhow!("no greeting, the client did not learn about the connection"))??;
        assert_eq!(&greeting, b"220 ready\r\n");

        stream.write_all(b"QUIT\r\n").await?;
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await?;
        assert_eq!(reply, b"221 bye\r\n");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unreachable_destination_resets_the_external_connection() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    // Nothing listens on the destination port yet.
    let destination = localhost(free_tcp_port());

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        destination,
        listen_port,
    );

    with_timeout(async {
        // The external client learns right away that there is nothing to talk to: the server
        // resets the connection, as close as it gets to "connection refused".
        let mut stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(
            tcp_end(&mut stream, Duration::from_secs(5)).await,
            TcpEnd::Reset
        );

        // Once the destination is up, the same tunnel forwards connections to it.
        tokio::spawn(serve_echo(TcpListener::bind(destination).await?));
        let stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(stream, b"hello".to_vec()).await?, b"hello");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connections_beyond_the_clients_limit_wait_for_a_free_slot() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let mut settings = client_settings(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );
    settings.max_connections = 1;
    let _client = spawn_client(settings);

    with_timeout(async {
        let mut first = connect_through_tunnel(listen_port).await?;
        echo_once(&mut first, b"first").await?;

        // The server accepts a second connection, but the client takes no second stream yet.
        let mut second = TcpStream::connect(localhost(listen_port)).await?;
        second.write_all(b"second").await?;
        let mut echoed = [0u8; 6];
        anyhow::ensure!(
            timeout(Duration::from_millis(500), second.read_exact(&mut echoed))
                .await
                .is_err(),
            "the client forwarded more connections than its limit"
        );

        // Once the first connection ends, the waiting one is forwarded, with the data it sent.
        drop(first);
        timeout(Duration::from_secs(5), second.read_exact(&mut echoed))
            .await
            .map_err(|_| anyhow!("the waiting connection was not forwarded"))??;
        assert_eq!(&echoed, b"second");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connections_beyond_the_servers_limit_wait_in_the_backlog() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let limits = ForwardingLimits {
        max_connections: 1,
        ..ForwardingLimits::default()
    };
    let _server = start_server_with_limits(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        limits,
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let mut first = connect_through_tunnel(listen_port).await?;
        echo_once(&mut first, b"first").await?;

        // The second connection is established by the system, but the server doesn't accept it.
        let mut second = TcpStream::connect(localhost(listen_port)).await?;
        second.write_all(b"second").await?;
        let mut echoed = [0u8; 6];
        anyhow::ensure!(
            timeout(Duration::from_millis(500), second.read_exact(&mut echoed))
                .await
                .is_err(),
            "the server forwarded more connections than its limit"
        );

        // Once the first connection ends, the server accepts the waiting one.
        drop(first);
        timeout(Duration::from_secs(5), second.read_exact(&mut echoed))
            .await
            .map_err(|_| anyhow!("the waiting connection was not forwarded"))??;
        assert_eq!(&echoed, b"second");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_waits_while_another_program_uses_its_port() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let other_program = std::net::TcpListener::bind(localhost(listen_port))?;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );

    with_timeout(async {
        // The server can't listen on the port and says so.
        let (_raw_client, raw) = connect_raw(config_dir.path(), quic_port).await?;
        let mut control_stream = authenticated_control_stream(&raw).await?;
        assert!(request_port(&mut control_stream, listen_port)
            .await
            .is_err());
        let end = raw.closed().await;
        assert_eq!(
            CloseCode::of(&end),
            Some(CloseCode::PortUnavailable),
            "{}",
            end
        );

        // That may be temporary, so the client keeps trying and gets the port once it is free.
        let client = start_client(
            config_dir.path(),
            quic_port,
            TEST_PSK,
            echo_addr,
            listen_port,
        );
        sleep(Duration::from_secs(1)).await;
        anyhow::ensure!(
            !client.task.is_finished(),
            "the client gave up: {:?}",
            client.result().await
        );
        drop(other_program);

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let attempt = async {
                let stream = connect_through_tunnel(listen_port).await?;
                echo_roundtrip(stream, b"free".to_vec()).await
            };
            if let Ok(Ok(echoed)) = timeout(Duration::from_secs(2), attempt).await {
                if echoed == b"free" {
                    break;
                }
            }
            anyhow::ensure!(Instant::now() < deadline, "client did not get the port");
            sleep(Duration::from_millis(100)).await;
        }
        client.stop().await
    })
    .await
}

#[tokio::test]
async fn new_connection_of_a_client_replaces_its_old_one() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let old_client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let mut forwarded = connect_through_tunnel(listen_port).await?;
        echo_once(&mut forwarded, b"old").await?;

        // E.g. the client restarted while the server still holds the port for its old
        // connection: the new connection gets the port right away.
        let (_new_client, new) = connect_raw(config_dir.path(), quic_port).await?;
        let mut control_stream = authenticated_control_stream(&new).await?;
        assert_eq!(
            request_port(&mut control_stream, listen_port).await?,
            listen_port
        );

        // The old connection is closed, with its forwarded connections.
        assert_eq!(
            tcp_end(&mut forwarded, Duration::from_secs(5)).await,
            TcpEnd::Reset
        );
        // The old client gives up: another instance with the same name is running.
        let error = format!("{:#}", old_client.result().await.unwrap_err());
        assert!(
            error.contains("another client with the same name took over the port"),
            "unexpected error: {}",
            error
        );

        // External connections go to the new connection now.
        let _external = connect_through_tunnel(listen_port).await?;
        let (_send, _recv) = timeout(Duration::from_secs(5), new.accept_bi()).await??;
        assert!(new.close_reason().is_none());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn standby_client_takes_over_when_the_active_one_stops() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    // Two clients may use the same port, with their own PSKs.
    let config = server_config_with_clients(
        config_dir.path(),
        quic_port,
        &[
            ("active", &["active-psk"], listen_port),
            ("standby", &["standby-psk"], listen_port),
        ],
    );
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);
    let active = start_named_client(
        config_dir.path(),
        quic_port,
        "active",
        "active-psk",
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(stream, b"active".to_vec()).await?, b"active");

        // The standby client doesn't take the port from the active one, but keeps trying.
        let standby = start_named_client(
            config_dir.path(),
            quic_port,
            "standby",
            "standby-psk",
            echo_addr,
            listen_port,
        );
        sleep(Duration::from_secs(1)).await;
        anyhow::ensure!(
            !standby.task.is_finished() && !active.task.is_finished(),
            "a client gave up"
        );
        let stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(stream, b"still".to_vec()).await?, b"still");

        // Once the active client is gone, the standby client gets the port.
        active.stop().await?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let attempt = async {
                let stream = connect_through_tunnel(listen_port).await?;
                echo_roundtrip(stream, b"standby".to_vec()).await
            };
            if let Ok(Ok(echoed)) = timeout(Duration::from_secs(2), attempt).await {
                if echoed == b"standby" {
                    break;
                }
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "standby client did not take over"
            );
            sleep(Duration::from_millis(100)).await;
        }
        standby.stop().await
    })
    .await
}

#[tokio::test]
async fn clients_need_their_own_psk_and_port() -> Result<()> {
    let config_dir = setup();
    let quic_port = free_udp_port();
    let (home_port, office_port) = (free_tcp_port(), free_tcp_port());
    let config = server_config_with_clients(
        config_dir.path(),
        quic_port,
        &[
            ("home", &["home-psk"], home_port),
            // While changing its PSK, the client may use either one.
            ("office", &["office-psk", "new-office-psk"], office_port),
        ],
    );
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);

    /// Authenticates as `name` with `psk` and returns why the server closed the connection.
    async fn rejection(
        config_dir: &Path,
        quic_port: u16,
        name: &str,
        psk: &str,
    ) -> Result<quinn::ConnectionError> {
        let (_client, connection) = connect_raw(config_dir, quic_port).await?;
        let result = authenticated_control_stream_as(&connection, name, psk).await;
        anyhow::ensure!(result.is_err(), "{} authenticated with {}", name, psk);
        Ok(connection.closed().await)
    }

    with_timeout(async {
        // The PSK of another client doesn't work, and an unknown name fails the same way, so the
        // server doesn't reveal which names exist.
        let wrong_psk = rejection(config_dir.path(), quic_port, "office", "home-psk").await?;
        let unknown_name = rejection(config_dir.path(), quic_port, "lab", "home-psk").await?;
        assert_eq!(
            CloseCode::of(&wrong_psk),
            Some(CloseCode::AuthenticationFailed),
            "{}",
            wrong_psk
        );
        assert_eq!(wrong_psk, unknown_name);

        // A client may only use its own port.
        let (_client, connection) = connect_raw(config_dir.path(), quic_port).await?;
        let mut control_stream =
            authenticated_control_stream_as(&connection, "home", "home-psk").await?;
        assert!(request_port(&mut control_stream, office_port)
            .await
            .is_err());
        let end = connection.closed().await;
        assert_eq!(
            CloseCode::of(&end),
            Some(CloseCode::PortNotAllowed),
            "{}",
            end
        );

        for psk in ["office-psk", "new-office-psk"] {
            let (_client, connection) = connect_raw(config_dir.path(), quic_port).await?;
            let mut control_stream =
                authenticated_control_stream_as(&connection, "office", psk).await?;
            assert_eq!(
                request_port(&mut control_stream, office_port).await?,
                office_port
            );
            connection.close(0u32.into(), b"done");
            connection.closed().await;
            wait_until_closed(office_port).await?;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn drain_stops_new_connections_but_keeps_running_ones() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );

    with_timeout(async {
        let (_draining_client, draining) = connect_raw(config_dir.path(), quic_port).await?;
        let mut control_stream = authenticated_control_stream(&draining).await?;
        request_port(&mut control_stream, listen_port).await?;
        let mut external = connect_through_tunnel(listen_port).await?;
        let (mut send, _recv) = draining.accept_bi().await?;

        // After DRAIN, the server accepts no new connections on the port...
        write_message(&mut control_stream, &Message::empty(MessageType::Drain)).await?;
        wait_until_closed(listen_port).await?;

        // ... but forwards the running ones and keeps the tunnel up.
        send.write_all(b"still forwarded").await?;
        let mut received = [0u8; 15];
        external.read_exact(&mut received).await?;
        assert_eq!(&received, b"still forwarded");
        write_message(&mut control_stream, &Message::empty(MessageType::Ping)).await?;
        let pong = read_message(&mut control_stream).await?.unwrap();
        assert_eq!(pong.kind, MessageType::Pong);

        // The port is free for another connection, which doesn't replace the draining one.
        let (_next_client, next) = connect_raw(config_dir.path(), quic_port).await?;
        let mut next_control_stream = authenticated_control_stream(&next).await?;
        assert_eq!(
            request_port(&mut next_control_stream, listen_port).await?,
            listen_port
        );
        assert!(draining.close_reason().is_none());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn external_reset_resets_the_destination_connection() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let (destination, mut accepted) = start_accepting_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        destination,
        listen_port,
    );

    with_timeout(async {
        let mut external = connect_through_tunnel(listen_port).await?;
        external.write_all(b"hello").await?;
        let mut destination_side = accepted.recv().await.unwrap();
        let mut hello = [0u8; 5];
        destination_side.read_exact(&mut hello).await?;

        // E.g. a browser that cancels a download.
        external.set_zero_linger()?;
        drop(external);

        assert_eq!(
            tcp_end(&mut destination_side, Duration::from_secs(5)).await,
            TcpEnd::Reset
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn destination_reset_resets_the_external_connection() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let (destination, mut accepted) = start_accepting_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        destination,
        listen_port,
    );

    with_timeout(async {
        let mut external = connect_through_tunnel(listen_port).await?;
        external.write_all(b"hello").await?;
        let mut destination_side = accepted.recv().await.unwrap();
        let mut hello = [0u8; 5];
        destination_side.read_exact(&mut hello).await?;
        destination_side.write_all(b"partial response").await?;

        // E.g. a backend that crashes in the middle of a response.
        destination_side.set_zero_linger()?;
        drop(destination_side);

        assert_eq!(
            tcp_end(&mut external, Duration::from_secs(5)).await,
            TcpEnd::Reset
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn lost_tunnel_resets_forwarded_connections() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let (destination, mut accepted) = start_accepting_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        destination,
        listen_port,
    );

    with_timeout(async {
        let mut external = connect_through_tunnel(listen_port).await?;
        external.write_all(b"hello").await?;
        let mut destination_side = accepted.recv().await.unwrap();
        let mut hello = [0u8; 5];
        destination_side.read_exact(&mut hello).await?;

        // The tunnel ends while the connection is running, so its transfers are incomplete.
        client.stop().await?;

        assert_eq!(
            tcp_end(&mut external, Duration::from_secs(5)).await,
            TcpEnd::Reset
        );
        assert_eq!(
            tcp_end(&mut destination_side, Duration::from_secs(5)).await,
            TcpEnd::Reset
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_aborts_streams_with_invalid_headers() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    // A server that sets up the tunnel normally, but starts a data stream with a malformed header.
    let (stream_ends, mut stream_end) = mpsc::unbounded_channel();
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        ForwardingLimits::default(),
    );
    let _server = spawn_server_with_handler(config, move |config, connection| {
        let stream_ends = stream_ends.clone();
        async move {
            let (mut control_stream, _client) =
                authenticate_quic_client(config, connection.clone()).await?;
            let hello = receive_hello(&mut control_stream).await?;
            let welcome = Greeting::new(SERVER_SOFTWARE, hello.listen_port);
            send_welcome(&mut control_stream, &welcome).await?;

            let (mut send, mut recv) = connection.open_bi().await?;
            // Three bytes of parameters, but a parameter needs at least four.
            send.write_all(&[0, 3, 0, 3, 0]).await?;
            let mut buf = [0u8; 16];
            let _ = stream_ends.send(recv.read(&mut buf).await);
            connection.closed().await;
            Ok(())
        }
    });
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        // The client aborts the stream instead of connecting to the destination.
        let end = stream_end.recv().await.unwrap();
        assert!(
            matches!(&end, Err(quinn::ReadError::Reset(code)) if code.into_inner() == 1),
            "{:?}",
            end
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_closes_connections_with_protocol_violations() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    // A server that answers HELLO with PONG on the first connection, and PING with WELCOME on
    // the second one.
    let (close_reasons, mut close_reason) = mpsc::unbounded_channel();
    let connection_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        ForwardingLimits::default(),
    );
    let _server = spawn_server_with_handler(config, move |config, connection| {
        let close_reasons = close_reasons.clone();
        let first = connection_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
        async move {
            let (mut control_stream, _client) =
                authenticate_quic_client(config, connection.clone()).await?;
            let hello = receive_hello(&mut control_stream).await?;
            if first {
                write_message(&mut control_stream, &Message::empty(MessageType::Pong)).await?;
            } else {
                let welcome = Greeting::new(SERVER_SOFTWARE, hello.listen_port);
                send_welcome(&mut control_stream, &welcome).await?;
                let ping = read_message(&mut control_stream).await?;
                anyhow::ensure!(ping.is_some_and(|m| m.kind == MessageType::Ping));
                let welcome_again = Message::new(MessageType::Welcome, Vec::new());
                write_message(&mut control_stream, &welcome_again).await?;
            }
            let _ = close_reasons.send(connection.closed().await);
            Ok(())
        }
    });
    let client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        for _ in 0..2 {
            let end = close_reason.recv().await.unwrap();
            assert_eq!(
                CloseCode::of(&end),
                Some(CloseCode::ProtocolViolation),
                "{}",
                end
            );
        }
        // The server may get fixed or replaced, so the client keeps trying.
        anyhow::ensure!(!client.task.is_finished(), "the client gave up");
        client.stop().await
    })
    .await
}

#[tokio::test]
async fn clients_of_other_protocol_versions_are_rejected() -> Result<()> {
    let config_dir = setup();
    let quic_port = free_udp_port();
    let _server = start_server(config_dir.path(), quic_port, vec![]);

    with_timeout(async {
        // Clients of protocol version 4, and clients that offer no version at all, fail the TLS
        // handshake, before they could send anything the server would misunderstand.
        for alpn in [Some(b"pr-4".as_slice()), None] {
            let certificate = std::fs::read(config_dir.path().join("cert.der"))?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(rustls::pki_types::CertificateDer::from(certificate))?;
            let mut crypto = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            crypto.alpn_protocols = alpn.into_iter().map(Vec::from).collect();
            let mut endpoint = quinn::Endpoint::client(localhost(0))?;
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
            )));

            let result = endpoint.connect(localhost(quic_port), CERT_HOSTNAME)?.await;

            let error = result.expect_err("handshake succeeded").to_string();
            assert!(
                error.contains("peer doesn't support any known protocol"),
                "{:?}: {}",
                alpn,
                error
            );
        }
        Ok(())
    })
    .await
}
#[tokio::test]
async fn server_closes_stalled_connections() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );

    with_timeout(async {
        // One client never answers the challenge, the other one authenticates but never asks
        // for a port. The server ends both after its timeouts of 10 seconds.
        let (_silent_client, silent) = connect_raw(config_dir.path(), quic_port).await?;
        let (_idle_client, idle) = connect_raw(config_dir.path(), quic_port).await?;
        let _control_stream = authenticated_control_stream(&idle).await?;

        let (silent_end, idle_end) = tokio::join!(silent.closed(), idle.closed());
        assert_eq!(
            CloseCode::of(&silent_end),
            Some(CloseCode::AuthenticationTimeout),
            "{}",
            silent_end
        );
        assert_eq!(
            CloseCode::of(&idle_end),
            Some(CloseCode::ConfigurationTimeout),
            "{}",
            idle_end
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn server_closes_connections_with_protocol_violations() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );

    with_timeout(async {
        // A malformed HELLO, and a listen port request of protocol version 4.
        for request in [&[1u8, 0, 3, 0, 2, 0][..], b"LISTENPORT\x01\xbb"] {
            let (_client, connection) = connect_raw(config_dir.path(), quic_port).await?;
            let mut control_stream = authenticated_control_stream(&connection).await?;
            control_stream.write_all(request).await?;
            control_stream.flush().await?;
            let end = connection.closed().await;
            assert_eq!(
                CloseCode::of(&end),
                Some(CloseCode::ProtocolViolation),
                "{}",
                end
            );
        }

        // An unexpected control message in an established tunnel.
        let (_second_client, second) = connect_raw(config_dir.path(), quic_port).await?;
        let mut control_stream = authenticated_control_stream(&second).await?;
        assert_eq!(
            request_port(&mut control_stream, listen_port).await?,
            listen_port
        );
        let hello_again = Message::new(MessageType::Hello, Vec::new());
        write_message(&mut control_stream, &hello_again).await?;
        let end = second.closed().await;
        assert_eq!(
            CloseCode::of(&end),
            Some(CloseCode::ProtocolViolation),
            "{}",
            end
        );

        // The server no longer listens on the port.
        wait_until_closed(listen_port).await
    })
    .await
}

#[tokio::test]
async fn client_rejects_server_without_psk() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    // A server that has the certificate's private key, but not the PSK: it accepts any proof
    // and answers with an invalid one. The messages follow docs/PROTOCOL.md.
    let (close_reasons, mut close_reason) = mpsc::unbounded_channel();
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        ForwardingLimits::default(),
    );
    let _server = spawn_server_with_handler(config, move |_, connection| {
        let close_reasons = close_reasons.clone();
        async move {
            let (mut send, mut recv) = connection.open_bi().await?;
            send.write_all(&[b"CHALLENGE".as_slice(), &[7u8; 32]].concat())
                .await?;
            // "RESPONSE", the name "default" with its length, and the proof.
            let mut response = [0u8; 8 + 1 + 7 + 32];
            recv.read_exact(&mut response).await?;
            anyhow::ensure!(
                response.starts_with(b"RESPONSE\x07default"),
                "unexpected response"
            );
            send.write_all(&[b"ACCEPTED".as_slice(), &[0u8; 32]].concat())
                .await?;
            let _ = close_reasons.send(connection.closed().await);
            Ok(())
        }
    });
    let client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        // The client gives up instead of trying again.
        let error = format!("{:#}", client.result().await.unwrap_err());
        assert!(
            error.contains("could not prove that it knows the PSK"),
            "unexpected error: {}",
            error
        );
        let end = close_reason.recv().await.unwrap();
        assert_eq!(
            CloseCode::of(&end),
            Some(CloseCode::AuthenticationFailed),
            "{}",
            end
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_gives_up_on_an_untrusted_certificate() -> Result<()> {
    let config_dir = setup();
    let other_certificate = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    // The client trusts another certificate than the server's.
    let client = start_client(
        other_certificate.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let error = format!("{:#}", client.result().await.unwrap_err());
        assert!(
            error.to_lowercase().contains("certificate"),
            "unexpected error: {}",
            error
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_gives_up_on_a_certificate_for_another_name() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    // The client trusts the server's certificate, but expects it to be issued for another name.
    let mut settings = client_settings(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );
    settings.quic_remote_hostname_match = Some("other.example".into());
    let client = spawn_client(settings);

    with_timeout(async {
        let error = format!("{:#}", client.result().await.unwrap_err());
        assert!(
            error.to_lowercase().contains("certificate"),
            "unexpected error: {}",
            error
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn failed_handshakes_block_address() -> Result<()> {
    let config_dir = setup();
    let other_certificate = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    let max_failures = BlockingPolicy::default().max_failures;

    with_timeout(async {
        // Clients that don't trust the server's certificate fail the TLS handshake.
        let mut failed_attempts = 0;
        loop {
            let result =
                connect_once(other_certificate.path(), quic_port, TEST_PSK, listen_port).await;
            if result.as_ref().is_err_and(|e| e.contains("refused")) {
                break;
            }
            failed_attempts += 1;
            anyhow::ensure!(
                failed_attempts <= max_failures + 2,
                "address not blocked after {} failed handshakes",
                failed_attempts
            );
        }
        anyhow::ensure!(
            failed_attempts >= max_failures,
            "address blocked after only {} failed handshakes",
            failed_attempts
        );

        // Then even a client with the right certificate and PSK is refused.
        let result = connect_once(config_dir.path(), quic_port, TEST_PSK, listen_port).await;
        assert!(
            result.as_ref().is_err_and(|e| e.contains("refused")),
            "unexpected result: {:?}",
            result
        );
        Ok(())
    })
    .await
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

#[tokio::test]
async fn stalled_handshake_does_not_hold_up_other_clients() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );

    with_timeout(async {
        let stalled = StalledHandshake::start(quic_port).await?;

        // Meanwhile, another client connects and forwards right away.
        let _client = start_client(
            config_dir.path(),
            quic_port,
            TEST_PSK,
            echo_addr,
            listen_port,
        );
        let stream = timeout(Duration::from_secs(5), connect_through_tunnel(listen_port))
            .await
            .map_err(|_| anyhow!("the stalled handshake held up the other client"))??;
        assert_eq!(echo_roundtrip(stream, b"hello".to_vec()).await?, b"hello");

        stalled.release().await
    })
    .await
}

#[tokio::test]
async fn stalled_handshakes_time_out_and_count_as_failed_attempts() -> Result<()> {
    let config_dir = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let mut config = server_config(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        ForwardingLimits::default(),
    );
    config.handshake_timeout = Duration::from_millis(500);
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);

    with_timeout(async {
        // Clients that stall their handshakes, e.g. to tie up the server's connection slots.
        let mut stalled = Vec::new();
        for _ in 0..BlockingPolicy::default().max_failures {
            stalled.push(StalledHandshake::start(quic_port).await?);
        }

        // The server gives up on them after its handshake timeout, while they still stall, and
        // counts each as a failed attempt, so the address is blocked now.
        sleep(Duration::from_millis(1500)).await;
        let result = connect_raw(config_dir.path(), quic_port).await;
        assert!(refused(&result), "unexpected result: {:?}", result.err());

        for client in stalled {
            client.release().await?;
        }
        Ok(())
    })
    .await
}

/// Keeps each connection open until the peer closes it.
async fn hold_connection(
    _config: Arc<ServerConfig<ServerAppData>>,
    connection: quinn::Connection,
) -> Result<()> {
    connection.closed().await;
    Ok(())
}

#[tokio::test]
async fn quic_connections_are_limited_in_total() -> Result<()> {
    let config_dir = setup();
    let quic_port = free_udp_port();
    let mut config = server_config(
        config_dir.path(),
        quic_port,
        vec![],
        ForwardingLimits::default(),
    );
    config.connection_limit = Some(2);
    let _server = spawn_server_with_handler(config, hold_connection);

    with_timeout(async {
        let (_first_client, first) = connect_raw(config_dir.path(), quic_port).await?;
        let (_second_client, _second) = connect_raw(config_dir.path(), quic_port).await?;
        let third = connect_raw(config_dir.path(), quic_port).await;
        assert!(refused(&third), "third connection: {:?}", third.err());

        // A closed connection makes room for a new one.
        first.close(0u32.into(), b"done");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match connect_raw(config_dir.path(), quic_port).await {
                Ok(_) => break,
                Err(e) if format!("{:#}", e).contains("refused") => {
                    anyhow::ensure!(
                        Instant::now() < deadline,
                        "no room after a closed connection"
                    );
                    sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })
    .await
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn quic_connections_are_limited_per_address() -> Result<()> {
    let config_dir = setup();
    let quic_port = free_udp_port();
    let (busy_host, other_host) = (Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3));
    let mut config = server_config(
        config_dir.path(),
        quic_port,
        vec![],
        ForwardingLimits::default(),
    );
    config.admission = QuicAdmission::new(2, BlockingPolicy::default());
    let _server = spawn_server_with_handler(config, hold_connection);

    with_timeout(async {
        let _first = connect_raw_from(config_dir.path(), quic_port, busy_host).await?;
        let _second = connect_raw_from(config_dir.path(), quic_port, busy_host).await?;
        let third = connect_raw_from(config_dir.path(), quic_port, busy_host).await;
        assert!(refused(&third), "third connection: {:?}", third.err());

        // Other addresses are not affected.
        let _other = connect_raw_from(config_dir.path(), quic_port, other_host).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn session_binding_is_shared_by_both_ends_and_unique_per_connection() -> Result<()> {
    let config_dir = setup();
    let quic_port = free_udp_port();
    let (connections, mut server_connections) = mpsc::unbounded_channel();
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![],
        ForwardingLimits::default(),
    );
    let _server = spawn_server_with_handler(config, move |_, connection| {
        let _ = connections.send(connection);
        async { Ok(()) }
    });

    with_timeout(async {
        let (_first_client, first) = connect_raw(config_dir.path(), quic_port).await?;
        let first_server_side = server_connections.recv().await.unwrap();
        let (_second_client, second) = connect_raw(config_dir.path(), quic_port).await?;
        let second_server_side = server_connections.recv().await.unwrap();

        // Both ends compute the same value, so the proofs match ...
        let binding = session_binding(&first)?;
        assert_eq!(binding, session_binding(&first_server_side)?);
        assert_eq!(
            session_binding(&second)?,
            session_binding(&second_server_side)?
        );
        // ... and it differs between connections, so a proof is worthless in another one.
        assert_ne!(binding, session_binding(&second)?);
        assert_ne!(binding, [0u8; 32]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn peer_dropping_a_stream_ends_forwarding_normally() -> Result<()> {
    let config_dir = setup();
    let quic_port = free_udp_port();
    let (connections, mut server_connections) = mpsc::unbounded_channel();
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![],
        ForwardingLimits::default(),
    );
    let _server = spawn_server_with_handler(config, move |_, connection| {
        let _ = connections.send(connection);
        async { Ok(()) }
    });

    with_timeout(async {
        let (_client, client_connection) = connect_raw(config_dir.path(), quic_port).await?;
        let server_connection = server_connections.recv().await.unwrap();

        // The server forwards a TCP connection through a stream, as for an external connection.
        let listener = TcpListener::bind(localhost(0)).await?;
        let mut tcp_peer = TcpStream::connect(listener.local_addr()?).await?;
        let (tcp_side, _) = listener.accept().await?;
        let (send, recv) = server_connection.open_bi().await?;
        let forwarding = tokio::spawn(forward_tcp_and_quic(
            tcp_side,
            send,
            recv,
            "test",
            DummyCounter::new(),
            DummyCounter::new(),
            None,
        ));
        tcp_peer.write_all(b"hello").await?;

        // The client drops the stream without reading it to the end, as it does after the
        // idle timeout. quinn then stops the stream with error code 0.
        let (client_send, mut client_recv) = client_connection.accept_bi().await?;
        let mut hello = [0u8; 5];
        client_recv.read_exact(&mut hello).await?;
        drop((client_send, client_recv));

        // The TCP side keeps sending until the forwarding notices.
        while !forwarding.is_finished() {
            if tcp_peer.write_all(&[0u8; 1024]).await.is_err() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        forwarding
            .await?
            .map_err(|e| e.context("a stream dropped by the peer counted as an error"))
    })
    .await
}
