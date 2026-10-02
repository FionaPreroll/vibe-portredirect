// Multiple Clients End-to-End Test for the PortRedirect/QUIC Client-Server Setup

use portredirect::app_data::{ClientAppData, ServerAppData};
use portredirect::quic::{client, server};
use portredirect::server::PortSpec;
use secrecy::SecretString;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::Notify;
use tokio::time::{timeout, Duration};
use tracing::info;

// This is an end-to-end test that sets up a QUIC server and multiple clients, and tests that they can
// successfully establish and hold multiple connections at the same time.
#[tokio::test]
async fn test_quic_end_to_end_multiple_clients() {
    // Initialize the tracing subscriber for logging
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer() // Ensures logs appear during `cargo test`
        .try_init();

    // Install the default crypto provider for QUIC
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Setup temporary config paths for certificates
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = temp_dir.path().to_path_buf();
    info!("Using config directory: {:?}", config_dir);

    // Define the test server port
    let test_port = 65501; // HACK statically chosen port

    // PSK is required so this tests needs one.
    let test_psk = "test_psk";
    let test_psk_server = SecretString::new(test_psk.into());
    let test_psk_client = SecretString::new(test_psk.into());

    // Create the server configuration.
    let server_app_data =
        ServerAppData::new(test_psk_server, "0.0.0.0".into(), vec![PortSpec::Single(0)]);
    let server_config: server::ServerConfig<ServerAppData> =
        server::ServerConfig::create_default_config(
            config_dir.clone(),
            "localhost".to_string(),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), test_port),
            Some(10),
            server_app_data,
        );
    info!("Server config: {:?}", server_config);

    // Create shared state for connection counting.
    let connection_counter = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());

    // Start the server task.
    // Each time the server accepts a connection, it will increment the counter and signal via notify.
    let server_counter = Arc::clone(&connection_counter);
    let notify_for_server = Arc::clone(&notify);
    info!("Starting server task");
    let server_handle = tokio::spawn(async move {
        info!("Server: Starting server");
        let result = server::run_quic_server(server_config, move |_, _conn| {
            // Clone the shared state into the connection callback.
            let notify_inner = Arc::clone(&notify_for_server);
            let counter_inner = Arc::clone(&server_counter);
            async move {
                info!("Server: New connection established");
                counter_inner.fetch_add(1, Ordering::SeqCst);
                notify_inner.notify_one();
                Ok(())
            }
        })
        .await;
        match result {
            Ok(_) => info!("Server finished successfully"),
            Err(e) => panic!("Server error: {:?}", e),
        }
    });

    // Spawn multiple client tasks.
    let num_clients = 5;
    let mut client_handles = Vec::with_capacity(num_clients);
    let client_app_data = ClientAppData::new(test_psk_client, "0.0.0.0:0".parse().unwrap());

    for i in 0..num_clients {
        // Each client gets its own configuration. (Note that we clone the config directory.)
        let app_data = client_app_data.clone();
        let client_config: client::ClientConfig<ClientAppData> =
            client::ClientConfig::create_default_config(
                config_dir.clone(),
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), test_port),
                Some("localhost".to_string()),
                Some(10),
                app_data,
            );
        info!("Client {} config: {:?}", i, client_config);

        let handle = tokio::spawn(async move {
            info!("Client {}: Starting client", i);
            match client::run_quic_client(client_config, move |_, _conn| async move {
                info!("Client {}: Connection established", i);
                Ok(())
            })
            .await
            {
                Ok(result) => result,
                Err(e) => panic!("Client {} error: {:?}", i, e),
            }
        });
        client_handles.push(handle);
    }

    // Wait until the server has seen all client connections.
    // We use a timeout to avoid hanging indefinitely.
    let timeout_duration = Duration::from_secs(5);
    let wait_all = timeout(timeout_duration, async {
        while connection_counter.load(Ordering::SeqCst) < num_clients {
            notify.notified().await;
        }
    })
    .await;
    assert!(
        wait_all.is_ok(),
        "Not all server connections were established in time"
    );
    info!("All {} connections established", num_clients);

    // Now wait for all client tasks to complete.
    for (i, handle) in client_handles.into_iter().enumerate() {
        let client_result = timeout(timeout_duration, handle).await;
        assert!(
            client_result.is_ok() && client_result.unwrap().is_ok(),
            "Client {} failed to complete",
            i
        );
    }

    // Tear down the server.
    server_handle.abort();
}
