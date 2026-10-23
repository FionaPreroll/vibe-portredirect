// End-to-end tests: Graceful shutdown of server and client.

use super::*;

#[tokio::test]
async fn client_shuts_down_cleanly() -> Result<()> {
    let (config_dir, _logs) = setup();
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
async fn server_shutdown_lets_running_connections_finish() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let shutdown = Shutdown::new(Duration::from_secs(60));
    let server = start_server_until(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        shutdown.clone(),
    );
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let mut running = connect_through_tunnel(listen_port).await?;
        echo_once(&mut running, b"before").await?;

        shutdown.drain();
        // The server accepts no new connections: neither external ones nor clients.
        wait_until_closed(listen_port).await?;
        let result = connect_raw(config_dir.path(), quic_port).await;
        assert!(refused(&result), "unexpected result: {:?}", result.err());

        // The running connection goes on.
        echo_once(&mut running, b"during").await?;
        assert!(!server.is_finished());

        // Once it ended, the server shuts down without waiting for the timeout.
        drop(running);
        ended(server, "server").await???;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn server_shutdown_closes_running_connections_after_the_timeout_or_on_request() -> Result<()>
{
    let (config_dir, _logs) = setup();
    let echo_addr = start_echo_server().await;

    // After the timeout, or when asked to stop before.
    for (shutdown_timeout, stop) in [
        (Duration::from_millis(500), false),
        (Duration::from_secs(60), true),
    ] {
        let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
        let shutdown = Shutdown::new(shutdown_timeout);
        let server = start_server_until(
            config_dir.path(),
            quic_port,
            vec![PortSpec::Single(listen_port)],
            shutdown.clone(),
        );
        let client = start_client(
            config_dir.path(),
            quic_port,
            TEST_PSK,
            echo_addr,
            listen_port,
        );

        with_timeout(async {
            let mut running = connect_through_tunnel(listen_port).await?;
            echo_once(&mut running, b"before").await?;

            let start = Instant::now();
            shutdown.drain();
            if stop {
                sleep(Duration::from_millis(500)).await;
                assert!(!server.is_finished());
                shutdown.stop();
            }
            ended(server, "server").await???;
            assert!(start.elapsed() >= Duration::from_millis(500));
            // The tunnel ended, so the running connection is reset.
            assert_eq!(
                tcp_end(&mut running, Duration::from_secs(5)).await,
                TcpEnd::Reset
            );

            // The client waits to connect again, and stops right away.
            ended(client.stop(), "client").await??;
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn client_shutdown_lets_running_connections_finish() -> Result<()> {
    let (config_dir, _logs) = setup();
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
    settings.shutdown = Shutdown::new(Duration::from_secs(60));
    let draining = spawn_client(settings);

    with_timeout(async {
        let mut running = connect_through_tunnel(listen_port).await?;
        echo_once(&mut running, b"before").await?;

        draining.shutdown.drain();
        // The server released the port right away: e.g. a new instance of the client takes it,
        // without replacing the draining one.
        wait_until_closed(listen_port).await?;
        let _new_instance = start_client(
            config_dir.path(),
            quic_port,
            TEST_PSK,
            echo_addr,
            listen_port,
        );
        let stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(stream, b"new".to_vec()).await?, b"new");

        // The running connection goes on.
        echo_once(&mut running, b"during").await?;
        assert!(!draining.task.is_finished());

        // Once it ended, the client shuts down without waiting for the timeout.
        drop(running);
        ended(draining.result(), "client").await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_shutdown_closes_running_connections_after_the_timeout_or_on_request() -> Result<()>
{
    let (config_dir, _logs) = setup();
    let echo_addr = start_echo_server().await;

    // After the timeout, or when asked to stop before.
    for (shutdown_timeout, stop) in [
        (Duration::from_millis(500), false),
        (Duration::from_secs(60), true),
    ] {
        let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
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
        settings.shutdown = Shutdown::new(shutdown_timeout);
        let client = spawn_client(settings);

        with_timeout(async {
            let mut running = connect_through_tunnel(listen_port).await?;
            echo_once(&mut running, b"before").await?;

            let start = Instant::now();
            client.shutdown.drain();
            if stop {
                sleep(Duration::from_millis(500)).await;
                assert!(!client.task.is_finished());
                client.shutdown.stop();
            }
            ended(client.result(), "client").await??;
            assert!(start.elapsed() >= Duration::from_millis(500));
            // The client closed its connection, so the server resets the running one.
            assert_eq!(
                tcp_end(&mut running, Duration::from_secs(5)).await,
                TcpEnd::Reset
            );
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn client_shuts_down_while_connecting() -> Result<()> {
    let (config_dir, _logs) = setup();
    // Nothing answers the client's handshake.
    let silent = std::net::UdpSocket::bind(localhost(0))?;
    let client = start_client(
        config_dir.path(),
        silent.local_addr()?.port(),
        TEST_PSK,
        localhost(1),
        free_tcp_port(),
    );

    with_timeout(async {
        sleep(Duration::from_millis(500)).await;
        assert!(!client.task.is_finished());
        ended(client.stop(), "client").await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_shuts_down_while_setting_up_the_tunnel() -> Result<()> {
    let (config_dir, _logs) = setup();
    let quic_port = free_udp_port();
    // The server authenticates the client, but never confirms the port.
    let (authenticated, authenticated_rx) = oneshot::channel::<()>();
    let authenticated = Arc::new(std::sync::Mutex::new(Some(authenticated)));
    let (closed, closed_rx) = oneshot::channel();
    let closed = Arc::new(std::sync::Mutex::new(Some(closed)));
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(free_tcp_port())],
        ForwardingLimits::default(),
    );
    let _server = spawn_server_with_handler(config, move |config, connection| {
        let (authenticated, closed) = (Arc::clone(&authenticated), Arc::clone(&closed));
        async move {
            let _control_stream = authenticate_quic_client(config, connection.clone()).await?;
            if let Some(authenticated) = authenticated.lock().unwrap().take() {
                let _ = authenticated.send(());
            }
            let reason = connection.closed().await;
            if let Some(closed) = closed.lock().unwrap().take() {
                let _ = closed.send(reason);
            }
            Ok(())
        }
    });
    let client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        localhost(1),
        free_tcp_port(),
    );

    with_timeout(async {
        authenticated_rx.await?;
        ended(client.stop(), "client").await??;
        // The client closed the connection normally.
        let reason = closed_rx.await?;
        assert_eq!(CloseCode::of(&reason), Some(CloseCode::Ok), "{:?}", reason);
        Ok(())
    })
    .await
}
