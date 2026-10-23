// End-to-end tests: Reconnecting clients, port takeover, standby clients and reloading the server configuration.

use super::*;

#[tokio::test]
async fn client_reconnects_after_server_restart() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let allowed_ports = vec![PortSpec::Single(listen_port)];

    let server_shutdown = Shutdown::default();
    let server = start_server_until(
        config_dir.path(),
        quic_port,
        allowed_ports.clone(),
        server_shutdown.clone(),
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
        server_shutdown.drain();
        server.await??;
        let _server = start_server_until(
            config_dir.path(),
            quic_port,
            allowed_ports,
            Shutdown::default(),
        );

        // The client reconnects and the tunnel works again.
        echo_once_the_tunnel_is_back(listen_port, b"after").await
    })
    .await
}

#[tokio::test]
async fn server_metrics_count_per_client() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    // The metrics are shared by all tests, but these clients only appear here.
    let mut config = server_config_with_clients(
        config_dir.path(),
        quic_port,
        &[
            ("metrics-a", &[TEST_PSK], listen_port),
            ("metrics-b", &["metrics-b-psk-0123456789"], free_tcp_port()),
        ],
    );
    config.app_data = config.app_data.with_forwarding_limits(ForwardingLimits {
        max_connections_per_ip: 1,
        ..ForwardingLimits::default()
    });
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);
    let client = start_named_client(
        config_dir.path(),
        quic_port,
        "metrics-a",
        TEST_PSK,
        echo_addr,
        listen_port,
    );
    let a: ClientMetrics = METRICS.client(&"metrics-a".parse().unwrap());
    let b = METRICS.client(&"metrics-b".parse().unwrap());
    let failures = METRICS.authentication_failures.get();

    with_timeout(async {
        let mut first = connect_through_tunnel(listen_port).await?;
        echo_once(&mut first, b"hello").await?;
        assert_eq!((a.tunnels.get(), a.tunnels_active.get()), (1, 1));
        assert_eq!(a.forwarded_connections_active.get(), 1);

        // A second connection from the same address is refused.
        let mut second = TcpStream::connect(localhost(listen_port)).await?;
        assert!(closed_by_peer(&mut second, Duration::from_secs(5)).await);
        assert_eq!(a.forwarded_connections_refused.address_limit.get(), 1);

        drop(first);
        wait_for_metric(
            || a.forwarded_connections_active.get(),
            0,
            "running connections",
        )
        .await?;
        assert_eq!(a.forwarded_connections.get(), 1);
        assert_eq!(a.bytes_from_external.get(), 5);
        assert_eq!(a.bytes_to_external.get(), 5);
        assert_eq!(a.forwarded_connections_aborted.get(), 0);

        // An external client that resets its connection aborts it.
        let reset = TcpStream::connect(localhost(listen_port)).await?;
        sleep(Duration::from_millis(200)).await;
        reset.set_zero_linger()?;
        drop(reset);
        wait_for_metric(
            || a.forwarded_connections_aborted.get() as i64,
            1,
            "aborted connections",
        )
        .await?;

        // A wrong PSK counts as failed attempt, without a client name.
        let result = connect_once(config_dir.path(), quic_port, "wrong-psk", listen_port).await;
        assert!(result.is_err(), "{:?}", result);
        assert!(METRICS.authentication_failures.get() > failures);

        client.stop().await?;
        wait_for_metric(|| a.tunnels_active.get(), 0, "active tunnels").await?;
        assert_eq!((a.keepalive_failures.get(), a.accept_errors.get()), (0, 0));

        // The other client's metrics are untouched.
        assert_eq!((b.tunnels.get(), b.forwarded_connections.get()), (0, 0));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_reconnects_when_the_server_ends_the_control_stream() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let (closed_tx, mut closed_rx) = mpsc::unbounded_channel();
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        ForwardingLimits::default(),
    );
    // A server that sets up the tunnel, then ends the control stream but not the connection.
    let _server = spawn_server_with_handler(config, move |config, connection| {
        let closed_tx = closed_tx.clone();
        async move {
            let (mut control_stream, _client) =
                authenticate_quic_client(config, connection.clone()).await?;
            let hello = receive_hello(&mut control_stream).await?;
            let welcome = Greeting::new(SERVER_SOFTWARE, hello.listen_port);
            send_welcome(&mut control_stream, &welcome).await?;
            drop(control_stream);
            let _ = closed_tx.send(connection.closed().await);
            Ok(())
        }
    });
    let failures = crate::client::metrics::METRICS.keepalive_failures.get();
    let _client = start_client(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        localhost(1),
        listen_port,
    );

    with_timeout(async {
        // The client closes each connection as failed keepalive, and connects again.
        for _ in 0..2 {
            let reason = closed_rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("the server ended"))?;
            assert_eq!(
                CloseCode::of(&reason),
                Some(CloseCode::KeepaliveFailed),
                "{:?}",
                reason
            );
        }
        let keepalive_failures = crate::client::metrics::METRICS.keepalive_failures.get();
        assert!(keepalive_failures >= failures + 2, "{}", keepalive_failures);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_waits_while_another_program_uses_its_port() -> Result<()> {
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
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
async fn reload_closes_the_tunnels_it_no_longer_accepts() -> Result<()> {
    let (config_dir, _logs) = setup();
    let quic_port = free_udp_port();
    let ports = [
        free_tcp_port(),
        free_tcp_port(),
        free_tcp_port(),
        free_tcp_port(),
    ];
    let echo_addr = start_echo_server().await;
    // The names keep the clients' metrics apart from other tests.
    let clients: [(&str, &str, u16); 4] = [
        ("reload-stays", "stays-psk-0123456789", ports[0]),
        ("reload-removed", "removed-psk-0123456789", ports[1]),
        ("reload-new-psk", "old-psk-0123456789", ports[2]),
        ("reload-moved", "moved-psk-0123456789", ports[3]),
    ];
    let accepted: Vec<(&str, &[&str], u16)> = clients
        .iter()
        .map(|(name, psk, port)| (*name, std::slice::from_ref(psk), *port))
        .collect();
    let config = server_config_with_clients(config_dir.path(), quic_port, &accepted);
    let app_data = config.app_data.clone();
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);
    let [stays, removed, new_psk, moved] = clients.map(|(name, psk, port)| {
        start_named_client(config_dir.path(), quic_port, name, psk, echo_addr, port)
    });

    with_timeout(async {
        for port in ports {
            echo_once_the_tunnel_is_back(port, b"up").await?;
        }

        // The configuration changes: one client gets a second PSK, one is removed, one has a
        // new PSK, and one another port.
        app_data.update(settings_with_clients(&[
            (
                "reload-stays",
                &["stays-psk-0123456789", "next-psk-0123456789"],
                ports[0],
            ),
            ("reload-new-psk", &["new-psk-0123456789"], ports[2]),
            ("reload-moved", &["moved-psk-0123456789"], free_tcp_port()),
        ])?);

        // The clients whose tunnels the server no longer accepts learn why, and give up.
        for (client, reason) in [
            (
                removed,
                "the client was removed from the server's configuration (code 1)",
            ),
            (
                new_psk,
                "the client's PSK was removed from the server's configuration (code 1)",
            ),
            (moved, "the client may no longer use the port (code 5)"),
        ] {
            let err = format!("{:#}", client.result().await.unwrap_err());
            assert!(err.contains(reason), "{}", err);
        }
        for port in &ports[1..] {
            wait_until_closed(*port).await?;
        }
        // The tunnel of the other client goes on.
        let stream = connect_through_tunnel(ports[0]).await?;
        assert_eq!(
            echo_roundtrip(stream, b"still up".to_vec()).await?,
            b"still up"
        );
        assert_eq!(tunnels_of("reload-stays"), 1);
        stays.stop().await
    })
    .await
}

#[tokio::test]
async fn psk_changes_without_a_restart_of_the_server() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let (name, old_psk, new_psk) = ("psk-change", "old-psk-0123456789", "new-psk-0123456789");
    let config = server_config_with_clients(
        config_dir.path(),
        quic_port,
        &[(name, &[old_psk], listen_port)],
    );
    let app_data = config.app_data.clone();
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);
    let client = start_named_client(
        config_dir.path(),
        quic_port,
        name,
        old_psk,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        echo_once_the_tunnel_is_back(listen_port, b"old PSK").await?;

        // 1. The server gets the new PSK, too, and keeps the tunnel.
        app_data.update(settings_with_clients(&[(
            name,
            &[old_psk, new_psk],
            listen_port,
        )])?);
        // 2. The client changes to the new PSK.
        client.stop().await?;
        let client = start_named_client(
            config_dir.path(),
            quic_port,
            name,
            new_psk,
            echo_addr,
            listen_port,
        );
        echo_once_the_tunnel_is_back(listen_port, b"new PSK").await?;
        // 3. The server drops the old PSK, which the tunnel doesn't use any more.
        app_data.update(settings_with_clients(&[(name, &[new_psk], listen_port)])?);

        let stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(
            echo_roundtrip(stream, b"still up".to_vec()).await?,
            b"still up"
        );
        assert_eq!(tunnels_of(name), 2);
        client.stop().await
    })
    .await
}

#[tokio::test]
async fn standby_client_takes_over_when_the_active_one_stops() -> Result<()> {
    let (config_dir, _logs) = setup();
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
