// End-to-end tests: Limits for connections and blocking of addresses after failed attempts.

use super::*;

#[cfg(target_os = "linux")]
#[tokio::test]
async fn connections_per_address_are_limited() -> Result<()> {
    let (config_dir, _logs) = setup();
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

#[tokio::test]
async fn new_connections_per_address_are_rate_limited() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let (busy_host, other_host) = (Ipv4Addr::new(127, 0, 0, 4), Ipv4Addr::new(127, 0, 0, 5));

    // Two connections at once, then one every half second. The client's name keeps its metrics
    // apart from other tests.
    let name = "rate-limited";
    let mut config = server_config_with_clients(
        config_dir.path(),
        quic_port,
        &[(name, &[TEST_PSK], listen_port)],
    );
    config.app_data = config.app_data.with_forwarding_limits(ForwardingLimits {
        max_connection_rate_per_ip: 2,
        max_connection_burst_per_ip: 2,
        ..ForwardingLimits::default()
    });
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);
    let metrics = METRICS.client(&name.parse().unwrap());
    let _client = start_named_client(
        config_dir.path(),
        quic_port,
        name,
        TEST_PSK,
        echo_addr,
        listen_port,
    );

    with_timeout(async {
        let ready = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(ready, b"ready".to_vec()).await?, b"ready");

        // Two connections from one address are forwarded, a third one right after is closed,
        // even though the first ones have ended.
        for message in [&b"first"[..], b"second"] {
            let mut stream = connect_from(busy_host, listen_port).await?;
            echo_once(&mut stream, message).await?;
        }
        let mut third = connect_from(busy_host, listen_port).await?;
        assert!(closed_by_peer(&mut third, Duration::from_secs(5)).await);
        assert_eq!(metrics.forwarded_connections_refused.rate_limit.get(), 1);
        assert_eq!(metrics.forwarded_connections_refused.address_limit.get(), 0);

        // Other addresses are not affected.
        let mut other = connect_from(other_host, listen_port).await?;
        echo_once(&mut other, b"other").await?;

        // Half a second later, the address may open another one.
        sleep(Duration::from_millis(600)).await;
        let mut later = connect_from(busy_host, listen_port).await?;
        echo_once(&mut later, b"later").await?;
        Ok(())
    })
    .await
}

/// Many idle connections from one host must not block the tunnel for others.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn idle_connections_from_one_address_do_not_block_others() -> Result<()> {
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
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
async fn connections_beyond_the_clients_limit_wait_for_a_free_slot() -> Result<()> {
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
    let (config_dir, _logs) = setup();
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
async fn failed_handshakes_block_address() -> Result<()> {
    let (config_dir, _logs) = setup();
    let other_certificate = certificate_dir();
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

#[tokio::test]
async fn stalled_handshake_does_not_hold_up_other_clients() -> Result<()> {
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
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

#[tokio::test]
async fn quic_connections_are_limited_in_total() -> Result<()> {
    let (config_dir, _logs) = setup();
    let quic_port = free_udp_port();
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![],
        ForwardingLimits::default(),
    );
    config.connection_limit.set(Some(2));
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

#[tokio::test]
async fn refusals_are_explained_once_on_both_sides() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (warnings, _warnings) = collect_logs("warn");
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        ForwardingLimits::default(),
    );
    config.connection_limit.set(Some(1));
    let _server = spawn_server_with_handler(config, hold_connection);

    with_timeout(async {
        // The only connection the server accepts.
        let (_first_client, _first) = connect_raw(config_dir.path(), quic_port).await?;
        let mut settings = client_settings(
            config_dir.path(),
            quic_port,
            TEST_PSK,
            localhost(9),
            listen_port,
        );
        settings.reconnect_backoff =
            Backoff::new(Duration::from_millis(10), Duration::from_millis(20));
        let client = spawn_client(settings);

        // The client keeps trying, ...
        let refused = |lines: &[String]| {
            lines
                .iter()
                .filter(|line| line.contains("the server refused to accept a new connection"))
                .count()
        };
        while refused(&warnings.lines()) < 3 {
            sleep(Duration::from_millis(10)).await;
        }
        client.stop().await?;

        // ... but explains the refusals only once, and the server warns about them once.
        let lines = warnings.lines();
        let count = |text: &str| lines.iter().filter(|line| line.contains(text)).count();
        assert_eq!(count(REFUSED_HINT), 1, "{:#?}", lines);
        let warning =
            "the server has 1 QUIC connections, the most it accepts (--max-quic-connections)";
        assert_eq!(count(warning), 1, "{:#?}", lines);
        Ok(())
    })
    .await
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn quic_connections_are_limited_per_address() -> Result<()> {
    let (config_dir, _logs) = setup();
    let quic_port = free_udp_port();
    let (busy_host, other_host) = (Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3));
    let mut config = server_config(
        config_dir.path(),
        quic_port,
        vec![],
        ForwardingLimits::default(),
    );
    config.admission = Arc::new(QuicAdmission::new(2, BlockingPolicy::default()));
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
