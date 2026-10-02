// PortRedirect Server - QUIC client handler
//
// License: GPL-3.0-only

use crate::protocol::control::configure_quic_client;
use crate::protocol::keepalive::run_control_channel_loop;
use crate::quic::server::ServerConfig;
use crate::server::AllowedPorts;
use crate::PortRedirectProtocol;
use crate::{app_data::ServerAppData, server::tcp_listener::handle_tcp_listener};

use super::auth::authenticate_quic_client;

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument};

// Handles one PR QUIC client connection.
// Called by run_quic_server.
#[instrument(skip(config, quic_conn))]
pub async fn handle_quic_client_connection(
    config: Arc<ServerConfig<ServerAppData>>,
    quic_conn: quinn::Connection,
) -> Result<()> {
    debug!(
        "Handling QUIC client connection from {}",
        quic_conn.remote_address()
    );

    // 1. Authenticate client.
    let control_stream = match timeout(
        PortRedirectProtocol::AUTHENTICATION_TIMEOUT,
        authenticate_quic_client(Arc::clone(&config), quic_conn.clone()),
    )
    .await
    {
        Ok(auth_result) => match auth_result {
            Ok(stream) => stream, // Auth succeeded. Return the control stream.
            Err(err) => {
                // Auth failed, close the connection.
                quic_conn.close(0u32.into(), b"ERR failed authentication");
                return Err(err).context(format!(
                    "failed to authenticate PR QUIC client from {}",
                    quic_conn.remote_address()
                ));
            }
        },
        Err(_) => {
            // Auth timed out, close the connection.
            quic_conn.close(0u32.into(), b"ERR authentication timed out");
            return Err(anyhow::anyhow!("authentication timed out")).context(format!(
                "authentication timeout for PR QUIC client from {}",
                quic_conn.remote_address()
            ));
        }
    };

    // 2. Receive config over control stream
    let (requested_client_config, control_stream) = match timeout(
        PortRedirectProtocol::CONFIGURATION_TIMEOUT,
        configure_quic_client(control_stream),
    )
    .await
    {
        Ok(result) => match result {
            Ok(result) => result,
            Err(err) => {
                quic_conn.close(0u32.into(), b"ERR failed configuration");
                return Err(err).context(format!(
                    "failed to receive configuration from {}",
                    quic_conn.remote_address()
                ));
            }
        },
        Err(_) => {
            quic_conn.close(0u32.into(), b"ERR configuration timed out");
            return Err(anyhow::anyhow!("configuration timed out")).context(format!(
                "configuration timeout from {}",
                quic_conn.remote_address()
            ));
        }
    };

    // Validate that the requested port is allowed.
    if !config
        .app_data
        .local_bind_ports
        .allows(requested_client_config.port)
    {
        quic_conn.close(0u32.into(), b"ERR port not allowed");
        return Err(anyhow::anyhow!(
            "requested port {} is not allowed",
            requested_client_config.port
        ));
    }

    // Create a cancellation token so the client can stop the TCP listener and end the QUIC connection.
    let cancel_token = CancellationToken::new();

    // 3. Create the TCP listener.
    let tcp_handle = {
        let tcp_addr =
            config.app_data.local_bind_ip.clone() + ":" + &requested_client_config.port.to_string();
        let listener = match TcpListener::bind(tcp_addr.clone()).await {
            Ok(listener) => listener,
            Err(err) => {
                // Terminate the connection upon failure to bind the TCP listener.
                quic_conn.close(0u32.into(), b"ERR failed binding tcp listener");
                return Err(err).context(format!("Failed to bind TCP listener to {}", tcp_addr));
            }
        };

        // Spawn the TCP listener in its own task.
        let tcp_config = Arc::clone(&config);
        let quic_conn_clone = quic_conn.clone();
        let cancel_token_clone = cancel_token.clone();
        tokio::spawn(async move {
            handle_tcp_listener(tcp_config, quic_conn_clone, listener, cancel_token_clone).await
        })
    };

    // 4. Run the control channel loop task.
    let control_channel_result = run_control_channel_loop(control_stream, cancel_token).await;

    // Close the QUIC connection after the control channel finishes.
    debug!(
        "Closing QUIC client connection from {}",
        quic_conn.remote_address()
    );
    quic_conn.close(0u32.into(), b"OK normal shutdown");

    // Await the TCP listener task.
    debug!("Waiting for TCP listener task to finish");
    tcp_handle.await??;

    debug!(
        "End of QUIC client connection from {}",
        quic_conn.remote_address()
    );

    control_channel_result
}
