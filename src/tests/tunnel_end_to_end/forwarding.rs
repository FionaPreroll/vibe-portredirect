// End-to-end tests: Forwarding data through the tunnel, in both directions, and how connections end.

use super::*;

#[tokio::test]
async fn tunnel_forwards_data_in_both_directions() -> Result<()> {
    let (config_dir, _logs) = setup();
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
async fn tunnel_forwards_data_with_bbr_on_both_sides() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    let mut config = server_config(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        ForwardingLimits::default(),
    );
    config.congestion_control = CongestionControl::Bbr;
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);
    let mut settings = client_settings(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );
    settings.congestion_control = CongestionControl::Bbr;
    let _client = spawn_client(settings);

    with_timeout(async {
        let payload = test_pattern(4 * 1024 * 1024, 2);
        let stream = connect_through_tunnel(listen_port).await?;
        let received = echo_roundtrip(stream, payload.clone()).await?;
        assert!(received == payload, "received data differs from sent data");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn tunnel_handles_concurrent_connections() -> Result<()> {
    let (config_dir, _logs) = setup();
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
async fn idle_connections_are_closed() -> Result<()> {
    let (config_dir, _logs) = setup();
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

#[tokio::test]
async fn server_resets_connections_for_which_the_client_accepts_no_stream() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let config = server_config_with_clients(
        config_dir.path(),
        quic_port,
        &[("no-streams", &[TEST_PSK], listen_port)],
    );
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);
    let metrics = METRICS.client(&"no-streams".parse().unwrap());

    with_timeout(async {
        // A client that lets the server open a single data stream, and never takes it.
        let client_config = ClientConfig::create_default_config(
            config_dir.path().to_path_buf(),
            localhost(0),
            localhost(quic_port),
            Some(CERT_HOSTNAME.into()),
            Some(1),
            ClientAppData::new(TEST_PSK.into(), localhost(1), 1),
        );
        let client = QuicClient::new(client_config)?;
        let connection = client.connect().await?;
        let mut control_stream =
            authenticated_control_stream_as(&connection, "no-streams", TEST_PSK).await?;
        request_port(&mut control_stream, listen_port).await?;

        let _first = TcpStream::connect(localhost(listen_port)).await?;
        let mut second = TcpStream::connect(localhost(listen_port)).await?;
        // The server waits 10 seconds for a stream, then resets the external connection.
        assert_eq!(
            tcp_end(&mut second, Duration::from_secs(15)).await,
            TcpEnd::Reset
        );
        assert_eq!(metrics.forwarded_connections_failed.get(), 1);
        assert_eq!(metrics.forwarded_connections.get(), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn responses_after_the_end_of_the_request_are_forwarded() -> Result<()> {
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    // Nothing listens on the destination port yet. The socket is bound, so no other test can
    // listen on the port meanwhile.
    let destination_socket = tokio::net::TcpSocket::new_v4()?;
    destination_socket.bind(localhost(0))?;
    let destination = destination_socket.local_addr()?;

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
        tokio::spawn(serve_echo(destination_socket.listen(16)?));
        let stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(stream, b"hello".to_vec()).await?, b"hello");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_logs_forwarded_connections() -> Result<()> {
    let (config_dir, _logs) = setup();
    // The connection log, which --log-connections switches on.
    let (connection_log, _connection_log) = collect_logs("portredirect::connections=info");
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    // Nothing listens on the destination port yet, see the test above.
    let destination_socket = tokio::net::TcpSocket::new_v4()?;
    destination_socket.bind(localhost(0))?;
    let destination = destination_socket.local_addr()?;

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
        // A connection the client can't forward.
        let mut stream = connect_through_tunnel(listen_port).await?;
        let external = stream.local_addr()?;
        assert_eq!(
            tcp_end(&mut stream, Duration::from_secs(5)).await,
            TcpEnd::Reset
        );
        let aborted = wait_for_lines(&connection_log, 2).await;
        let connection = format!("external_client={} destination={}", external, destination);
        assert!(
            aborted[0].ends_with(&format!("Connection opened {}", connection)),
            "{}",
            aborted[0]
        );
        assert!(
            aborted[1].contains(&format!("Connection aborted {} duration_ms=", connection))
                && aborted[1].contains("bytes_to_destination=0 bytes_from_destination=0")
                && aborted[1].contains("error=failed to connect to destination"),
            "{}",
            aborted[1]
        );

        // A connection it forwards.
        tokio::spawn(serve_echo(destination_socket.listen(16)?));
        let stream = connect_through_tunnel(listen_port).await?;
        let external = stream.local_addr()?;
        assert_eq!(echo_roundtrip(stream, b"hello".to_vec()).await?, b"hello");
        let closed = wait_for_lines(&connection_log, 4).await;
        let connection = format!("external_client={} destination={}", external, destination);
        assert!(closed[2].ends_with(&format!("Connection opened {}", connection)));
        assert!(
            closed[3].contains(&format!("Connection closed {} duration_ms=", connection))
                && closed[3].ends_with("bytes_to_destination=5 bytes_from_destination=5"),
            "{}",
            closed[3]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn tunnel_works_over_ipv6() -> Result<()> {
    if !ipv6_available() {
        return Ok(());
    }
    let (config_dir, _logs) = setup();
    let (connection_log, _connection_log) = collect_logs("portredirect::connections=info");
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let destination = TcpListener::bind(ipv6_localhost(0)).await?;
    let destination_addr = destination.local_addr()?;
    tokio::spawn(serve_echo(destination));

    // The server only listens on ::1, for QUIC and for external connections.
    let ports = vec![PortSpec::Single(listen_port)];
    let quic = ipv6_localhost(quic_port);
    let limits = ForwardingLimits::default();
    let config = server_config_on(config_dir.path(), quic, "::1", ports, limits);
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);
    // The client sends from any address, to the server's address in brackets, as in URLs.
    let mut settings = client_settings(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        destination_addr,
        listen_port,
    );
    settings.quic_local = LocalAddress::Any { port: 0 };
    settings.quic_remote = HostPort::new("[::1]", quic_port);
    let _client = spawn_client(settings);

    with_timeout(async {
        let stream = connect_through_tunnel_at(ipv6_localhost(listen_port)).await?;
        let external = stream.local_addr()?;
        let echoed = echo_roundtrip(stream, b"over IPv6".to_vec()).await?;
        assert_eq!(echoed, b"over IPv6");
        // The client learns the external client's IPv6 address.
        let opened = wait_for_lines(&connection_log, 1).await;
        let expected = format!(
            "Connection opened external_client={} destination={}",
            external, destination_addr
        );
        assert!(opened[0].ends_with(&expected), "{}", opened[0]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn server_on_any_ipv6_address_accepts_ipv4_too() -> Result<()> {
    if !ipv6_available() {
        return Ok(());
    }
    let (config_dir, _logs) = setup();
    // The server's messages, with its peers' addresses, and the client's connection log.
    let (logs, _collected) = collect_logs("portredirect=debug,portredirect::connections=info");
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;

    // The server listens on ::, for QUIC and for external connections, and forwards a single
    // connection per address at a time.
    let ports = vec![PortSpec::Single(listen_port)];
    let quic = SocketAddr::from((Ipv6Addr::UNSPECIFIED, quic_port));
    let limits = ForwardingLimits {
        max_connections_per_ip: 1,
        ..ForwardingLimits::default()
    };
    let config = server_config_on(config_dir.path(), quic, "::", ports, limits);
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);
    // The client connects over IPv4, to 127.0.0.1.
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

        // External clients over IPv4 count under their IPv4 addresses: while one connection of
        // 127.0.0.2 is forwarded, the server closes a second one, but not one of 127.0.0.3. Under
        // their IPv4-mapped IPv6 addresses, they would share a /64 network.
        let (busy_host, other_host) = (Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3));
        let mut first = connect_from(busy_host, listen_port).await?;
        echo_once(&mut first, b"first").await?;
        let mut second = connect_from(busy_host, listen_port).await?;
        assert!(closed_by_peer(&mut second, Duration::from_secs(5)).await);
        let mut other = connect_from(other_host, listen_port).await?;
        echo_once(&mut other, b"other").await?;
        // External clients over IPv6.
        let mut over_ipv6 = TcpStream::connect(ipv6_localhost(listen_port)).await?;
        echo_once(&mut over_ipv6, b"over IPv6").await?;

        // The logs write IPv4 addresses as such, not as IPv4-mapped IPv6 addresses.
        let lines = logs.lines();
        for external in [
            first.local_addr()?,
            other.local_addr()?,
            over_ipv6.local_addr()?,
        ] {
            let opened = format!("Connection opened external_client={} ", external);
            assert!(
                lines.iter().any(|line| line.contains(&opened)),
                "{:#?}",
                lines
            );
        }
        let mapped: Vec<_> = lines
            .iter()
            .filter(|line| line.contains("::ffff:"))
            .collect();
        assert!(mapped.is_empty(), "{:#?}", mapped);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn drain_stops_new_connections_but_keeps_running_ones() -> Result<()> {
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
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
async fn peer_dropping_a_stream_ends_forwarding_normally() -> Result<()> {
    let (config_dir, _logs) = setup();
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
