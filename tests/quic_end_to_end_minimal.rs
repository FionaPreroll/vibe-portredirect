// Minimal End-to-End Test for the PortRedirect/QUIC Client-Server Setup

use anyhow::Error;
use portredirect::app_data::{ClientAppData, ServerAppData};
use portredirect::quic::{client, server};
use portredirect::server::PortSpec;
use secrecy::SecretString;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::{timeout, Duration};
use tracing::info;

// This is an end-to-end test that sets up a QUIC server and client, and tests that they can
// successfully establish a connection. The server and client are run in separate tasks, and the
// test waits for the server and client to signal that a connection has been established.
#[tokio::test]
async fn test_quic_end_to_end_minimal() {
    // Initialize the tracing subscriber for logging
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer() // Ensures logs appear during `cargo test`
        .try_init();

    // Install the default crypto provider for QUIC
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // PSK is required so this tests needs one.
    let test_psk = "test_psk";
    let test_psk_server = SecretString::new(test_psk.into());
    let test_psk_client = SecretString::new(test_psk.into());

    // Setup temporary config paths for certificates
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = temp_dir.path().to_path_buf();
    info!("Using config directory: {:?}", config_dir);

    // Define server and client configuration
    let server_app_data = ServerAppData::new(test_psk_server, "0.0.0.0".into(), vec![PortSpec::Single(0)]);
    let test_port = 65500; // HACK statically chosen port
    let server_config: server::ServerConfig<ServerAppData> =
        server::ServerConfig::create_default_config(
            config_dir.clone(),
            "localhost".to_string(),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), test_port), // QUIC socket
            None,
            server_app_data,
        );
    info!("Server config: {:?}", server_config);

    let client_app_data = ClientAppData::new(test_psk_client, "0.0.0.0:0".parse().unwrap());
    let client_config: client::ClientConfig<ClientAppData> =
        client::ClientConfig::create_default_config(
            config_dir,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), test_port),
            Some("localhost".to_string()),
            None,
            client_app_data,
        );
    info!("Client config: {:?}", client_config);

    // Create a Notify instance to signal when a connection is established.
    let notify = Arc::new(Notify::new());
    let notify_clone = Arc::clone(&notify);

    info!("Starting server task");
    let server_handle = tokio::spawn(async move {
        info!("Server: Starting server");
        match server::run_quic_server(server_config, move |_, _conn| {
            let notify_inner = Arc::clone(&notify_clone);
            async move {
                info!("Server: New connection established");
                notify_inner.notify_one();
                Ok(())
            }
        })
        .await
        {
            Ok(_) => info!("Server finished successfully"),
            Err(e) => panic!("Server error: {:?}", e),
        }
    });

    info!("Starting client task");
    let client_handle: tokio::task::JoinHandle<Result<(), Error>> = tokio::spawn(async move {
        info!("Client: Starting client");
        match client::run_quic_client(client_config, |_, _conn| async move {
            info!("Client: Connection established");
            Ok(())
        })
        .await
        {
            Ok(result) => Ok(result),
            Err(e) => panic!("Client error: {:?}", e),
        }
    });

    info!("Waiting for server and client to signal connection (5s timeout)");
    let notify_result = timeout(Duration::from_secs(5), notify.notified()).await;
    assert!(
        notify_result.is_ok(),
        "Server did not signal within timeout"
    );
    info!("Server and client signaled connection!");

    // Await the client result with a timeout.
    info!("Waiting for client to finish (5s timeout)");
    let client_result = timeout(Duration::from_secs(5), client_handle).await;
    assert!(
        client_result.is_ok() && client_result.unwrap().is_ok(),
        "Client failed to connect within timeout"
    );

    // Tear down server.
    server_handle.abort();
}
