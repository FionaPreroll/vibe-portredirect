// End-to-end tests: Keepalive and the handling of protocol violations.

use super::*;

#[tokio::test]
async fn client_aborts_streams_with_invalid_headers() -> Result<()> {
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
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
async fn server_closes_stalled_connections() -> Result<()> {
    let (config_dir, _logs) = setup();
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
async fn server_ends_tunnels_whose_keepalive_fails() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    // The name keeps the client's metrics apart from other tests.
    let (name, psk) = ("keepalive-silent", "keepalive-psk-0123456789");
    let mut config =
        server_config_with_clients(config_dir.path(), quic_port, &[(name, &[psk], listen_port)]);
    // Instead of a minute.
    config.keepalive_timeout = Duration::from_millis(500);
    let _server = spawn_server_with_handler(config, handle_quic_client_connection);
    let metrics = METRICS.client(&name.parse().unwrap());
    let failures = metrics.keepalive_failures.get();

    with_timeout(async {
        // The client sets up the tunnel, but never sends a PING.
        let (_client, connection) = connect_raw(config_dir.path(), quic_port).await?;
        let mut control_stream = authenticated_control_stream_as(&connection, name, psk).await?;
        assert_eq!(
            request_port(&mut control_stream, listen_port).await?,
            listen_port
        );
        let end = connection.closed().await;
        assert_eq!(
            CloseCode::of(&end),
            Some(CloseCode::KeepaliveFailed),
            "{}",
            end
        );
        assert!(end.to_string().contains("keepalive timed out"), "{}", end);

        // The server releases the port and counts the failure.
        wait_until_closed(listen_port).await?;
        assert_eq!(metrics.keepalive_failures.get(), failures + 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn server_closes_connections_with_protocol_violations() -> Result<()> {
    let (config_dir, _logs) = setup();
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
async fn server_closes_connections_before_their_control_streams_end() -> Result<()> {
    // Otherwise the client could read the end of the control stream before the reason, e.g. a
    // protocol violation, and take it for a failed keepalive.
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let (closed_before, mut closed_before_end) = mpsc::unbounded_channel();
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        ForwardingLimits::default(),
    );
    let _server = spawn_server_with_handler(config, move |config, connection| {
        let closed_before = closed_before.clone();
        async move {
            let (stream, client) =
                authenticate_quic_client(Arc::clone(&config), connection.clone()).await?;
            let read = EndWatch {
                read: stream.read,
                connection: connection.clone(),
                closed_before,
            };
            let control_stream = BiStream::new(read, stream.write, stream.name);
            serve_client(config, connection, control_stream, client).await
        }
    });

    with_timeout(async {
        // A malformed HELLO, and an unexpected message in an established tunnel.
        for established in [false, true] {
            let (_client, connection) = connect_raw(config_dir.path(), quic_port).await?;
            let mut control_stream = authenticated_control_stream(&connection).await?;
            if established {
                request_port(&mut control_stream, listen_port).await?;
                let hello_again = Message::new(MessageType::Hello, Vec::new());
                write_message(&mut control_stream, &hello_again).await?;
            } else {
                control_stream.write_all(&[1, 0, 3, 0, 2, 0]).await?;
                control_stream.flush().await?;
            }
            let end = connection.closed().await;
            assert_eq!(
                CloseCode::of(&end),
                Some(CloseCode::ProtocolViolation),
                "{}",
                end
            );
            assert!(
                closed_before_end.recv().await.unwrap(),
                "the control stream ended before the connection was closed (established: {})",
                established
            );
        }
        Ok(())
    })
    .await
}
