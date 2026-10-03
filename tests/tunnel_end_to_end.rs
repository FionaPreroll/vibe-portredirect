// End-to-End Tests of a complete PortRedirect tunnel.
//
// Unlike the minimal QUIC tests, these run the real server and client connection handlers:
// authentication, control channel, TCP listener and data forwarding.

use anyhow::{anyhow, Result};
use portredirect::app_data::{ClientAppData, ServerAppData};
use portredirect::client::reconnect::Backoff;
use portredirect::client::run_client::{run_client, ClientSettings};
use portredirect::client::server_handler::handle_quic_server_connection;
use portredirect::limits::BlockingPolicy;
use portredirect::quic::client::{run_quic_client, ClientConfig};
use portredirect::quic::server::{
    load_or_generate_quic_cert, run_quic_server, run_quic_server_until, ServerConfig,
};
use portredirect::server::client_handler::handle_quic_client_connection;
use portredirect::server::{ForwardingLimits, PortSpec};
use portredirect::PortRedirectProtocol;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Duration, Instant};

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
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
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

fn start_server_with_limits(
    config_dir: &Path,
    quic_port: u16,
    allowed_ports: Vec<PortSpec>,
    limits: ForwardingLimits,
) -> JoinHandle<()> {
    let config = server_config(config_dir, quic_port, allowed_ports, limits);
    tokio::spawn(async move {
        run_quic_server(config, handle_quic_client_connection)
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

/// Starts a client with short reconnection delays.
fn start_client(
    config_dir: &Path,
    quic_port: u16,
    psk: &str,
    destination: SocketAddr,
    remote_listen_port: u16,
) -> TestClient {
    let settings = ClientSettings {
        app_data: ClientAppData::new(psk.into(), destination, remote_listen_port),
        config_dir: config_dir.to_path_buf(),
        quic_local_addr: localhost(0),
        quic_remote_addr: localhost(quic_port),
        quic_remote_hostname_match: Some(CERT_HOSTNAME.into()),
        max_connections: PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS,
        metrics_addr: None,
        reconnect_backoff: Backoff::new(Duration::from_millis(100), Duration::from_secs(1)),
    };
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

        // Without transfers, the server closes it.
        assert!(closed_by_peer(&mut stream, Duration::from_secs(5)).await);
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
