// End-to-end tests: Authentication of clients and of the server, and what an unauthenticated peer may do.

use super::*;

#[tokio::test]
async fn unauthenticated_clients_can_only_send_a_little() -> Result<()> {
    let (config_dir, _logs) = setup();
    let quic_port = free_udp_port();

    // Like the server's handler before the authentication: opens a stream, and doesn't read
    // what the client sends, until the test raises the receive window, like after it.
    let (raise, raised) = mpsc::channel::<()>(1);
    let raised = Arc::new(tokio::sync::Mutex::new(raised));
    let config = server_config(config_dir.path(), quic_port, vec![], Default::default());
    let _server = spawn_server_with_handler(config, move |_, connection| {
        let raised = Arc::clone(&raised);
        async move {
            let (mut send, _recv) = connection.open_bi().await?;
            // The client learns about the stream with its first data.
            send.write_all(b"!").await?;
            raised.lock().await.recv().await;
            raise_receive_window(&connection);
            connection.closed().await;
            Ok(())
        }
    });

    with_timeout(async {
        let (_client, connection) = connect_raw(config_dir.path(), quic_port).await?;
        let (mut send, mut recv) = connection.accept_bi().await?;
        recv.read_exact(&mut [0u8; 1]).await?;
        let window = PortRedirectProtocol::QUIC_UNAUTHENTICATED_RECEIVE_WINDOW as usize;

        let before = write_until_blocked(&mut send, 1 << 20).await?;
        assert_eq!(before, window);

        raise.send(()).await?;
        let after = write_until_blocked(&mut send, 1 << 20).await?;
        assert_eq!(after, 1 << 20);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn authenticated_clients_may_send_more() -> Result<()> {
    let (config_dir, _logs) = setup();
    let quic_port = free_udp_port();

    // Authenticates the client like the server, then reads nothing more.
    let config = server_config(config_dir.path(), quic_port, vec![], Default::default());
    let _server = spawn_server_with_handler(config, |config, connection| async move {
        let _authenticated = authenticate_quic_client(config, connection.clone()).await?;
        connection.closed().await;
        Ok(())
    });

    with_timeout(async {
        let (_client, connection) = connect_raw(config_dir.path(), quic_port).await?;
        let mut control_stream = authenticated_control_stream(&connection).await?;
        let written = write_until_blocked(&mut control_stream, 1 << 20).await?;
        assert_eq!(written, 1 << 20);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn server_rejects_wrong_psk() -> Result<()> {
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
async fn rejected_client_learns_why_before_its_control_stream_ends() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let config = server_config(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
        ForwardingLimits::default(),
    );
    // A server that takes a while after a failed authentication, e.g. as it is busy. Meanwhile,
    // the control stream ends, so the reason must have been sent before.
    let _server = spawn_server_with_handler(config, |config, connection| async move {
        let authenticated = authenticate_quic_client(config, connection).await;
        sleep(Duration::from_millis(200)).await;
        authenticated.map(|_| ())
    });
    let client = start_client(
        config_dir.path(),
        quic_port,
        "wrong-psk",
        localhost(1),
        listen_port,
    );

    with_timeout(async {
        // Without the reason, the client would take the end for a temporary failure.
        let error = format!("{:#}", client.result().await.unwrap_err());
        assert!(
            error.contains("authentication failed (code 1)"),
            "unexpected error: {}",
            error
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn server_rejects_disallowed_port() -> Result<()> {
    let (config_dir, _logs) = setup();
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
async fn client_trusts_the_server_by_the_fingerprint_of_its_certificate() -> Result<()> {
    let (config_dir, _logs) = setup();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    // The client has no copy of the certificate.
    let client_dir = tempfile::tempdir()?;
    let mut settings = client_settings(
        client_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );
    settings.cert_fingerprints = vec![fingerprint_of(&config_dir)?];
    let _client = spawn_client(settings);

    with_timeout(async {
        let stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(stream, b"pinned".to_vec()).await?, b"pinned");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_gives_up_on_a_certificate_with_another_fingerprint() -> Result<()> {
    let (config_dir, _logs) = setup();
    let other_certificate = certificate_dir();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let _server = start_server(
        config_dir.path(),
        quic_port,
        vec![PortSpec::Single(listen_port)],
    );
    // The client trusts the server's certificate by cert.der, but its fingerprint takes
    // precedence.
    let mut settings = client_settings(
        config_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );
    settings.cert_fingerprints = vec![fingerprint_of(&other_certificate)?];
    let client = spawn_client(settings);

    with_timeout(async {
        let error = format!("{:#}", client.result().await.unwrap_err());
        let fingerprint = fingerprint_of(&config_dir)?.to_string();
        assert!(error.contains(&fingerprint), "unexpected error: {}", error);
        assert!(error.contains("giving up"), "unexpected error: {}", error);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn server_certificate_changes_while_clients_trust_both_fingerprints() -> Result<()> {
    let (old_certificate, _logs) = setup();
    let new_certificate = certificate_dir();
    let (quic_port, listen_port) = (free_udp_port(), free_tcp_port());
    let echo_addr = start_echo_server().await;
    let allowed_ports = vec![PortSpec::Single(listen_port)];

    let old_server_shutdown = Shutdown::default();
    let old_server = start_server_until(
        old_certificate.path(),
        quic_port,
        allowed_ports.clone(),
        old_server_shutdown.clone(),
    );
    // While the certificate changes, the client trusts both.
    let client_dir = tempfile::tempdir()?;
    let mut settings = client_settings(
        client_dir.path(),
        quic_port,
        TEST_PSK,
        echo_addr,
        listen_port,
    );
    settings.cert_fingerprints = vec![
        fingerprint_of(&old_certificate)?,
        fingerprint_of(&new_certificate)?,
    ];
    let _client = spawn_client(settings);

    with_timeout(async {
        let stream = connect_through_tunnel(listen_port).await?;
        assert_eq!(echo_roundtrip(stream, b"old".to_vec()).await?, b"old");

        // The server restarts with the new certificate, and the client reconnects.
        old_server_shutdown.drain();
        old_server.await??;
        let _new_server = start_server_until(
            new_certificate.path(),
            quic_port,
            allowed_ports,
            Shutdown::default(),
        );
        echo_once_the_tunnel_is_back(listen_port, b"new").await
    })
    .await
}

#[tokio::test]
async fn clients_need_their_own_psk_and_port() -> Result<()> {
    let (config_dir, _logs) = setup();
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
async fn clients_of_other_protocol_versions_are_rejected() -> Result<()> {
    let (config_dir, _logs) = setup();
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
async fn client_rejects_server_without_psk() -> Result<()> {
    let (config_dir, _logs) = setup();
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
    let (config_dir, _logs) = setup();
    let other_certificate = certificate_dir();
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
    let (config_dir, _logs) = setup();
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
    settings.quic_cert_hostname = Some("other.example".into());
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
async fn session_binding_is_shared_by_both_ends_and_unique_per_connection() -> Result<()> {
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
