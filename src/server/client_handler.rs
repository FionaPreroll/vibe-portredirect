// PortRedirect Server - QUIC client handler
//
// License: GPL-3.0-only

use crate::protocol::close::CloseCode;
use crate::protocol::control::{configure_quic_client, confirm_client_configuration};
use crate::protocol::keepalive::{run_control_channel_loop, ControlChannelEnd};
use crate::quic::server::ServerConfig;
use crate::server::AllowedPorts;
use crate::PortRedirectProtocol;
use crate::{app_data::ServerAppData, server::tcp_listener::handle_tcp_listener};

use super::auth::authenticate_quic_client;

use anyhow::{anyhow, Context, Result};
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
    let remote = quic_conn.remote_address();
    debug!("Handling QUIC client connection from {}", remote);

    // 1. Authenticate client.
    let control_stream = match timeout(
        PortRedirectProtocol::AUTHENTICATION_TIMEOUT,
        authenticate_quic_client(Arc::clone(&config), quic_conn.clone()),
    )
    .await
    {
        Ok(Ok(stream)) => {
            // Auth succeeded. Continue with the control stream.
            config.admission.record_success(remote.ip());
            stream
        }
        Ok(Err(err)) => {
            config.admission.record_failure(remote.ip());
            CloseCode::AuthenticationFailed.close(&quic_conn, "authentication failed");
            return Err(err).context(format!(
                "failed to authenticate PR QUIC client from {}",
                remote
            ));
        }
        Err(_) => {
            config.admission.record_failure(remote.ip());
            CloseCode::AuthenticationTimeout.close(&quic_conn, "authentication timed out");
            return Err(anyhow!("authentication timed out")).context(format!(
                "authentication timeout for PR QUIC client from {}",
                remote
            ));
        }
    };

    // 2. Receive config over control stream
    let (requested_client_config, mut control_stream) = match timeout(
        PortRedirectProtocol::CONFIGURATION_TIMEOUT,
        configure_quic_client(control_stream),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => {
            CloseCode::ProtocolViolation.close(&quic_conn, "invalid listen port request");
            return Err(err).context(format!("failed to receive configuration from {}", remote));
        }
        Err(_) => {
            CloseCode::ConfigurationTimeout.close(&quic_conn, "configuration timed out");
            return Err(anyhow!("configuration timed out"))
                .context(format!("configuration timeout from {}", remote));
        }
    };

    // Validate that the requested port is allowed.
    let port = requested_client_config.port;
    if !config.app_data.local_bind_ports.allows(port) {
        CloseCode::PortNotAllowed.close(&quic_conn, "port not allowed");
        return Err(anyhow!("requested port {} is not allowed", port));
    }

    // Create a cancellation token so the client can stop the TCP listener and end the QUIC connection.
    let cancel_token = CancellationToken::new();

    // 3. Create the TCP listener.
    let tcp_handle = {
        let tcp_addr = config.app_data.local_bind_ip.clone() + ":" + &port.to_string();
        let listener = match TcpListener::bind(tcp_addr.clone()).await {
            Ok(listener) => listener,
            Err(err) => {
                // Terminate the connection upon failure to bind the TCP listener.
                CloseCode::PortUnavailable.close(&quic_conn, "failed to listen on port");
                return Err(err).context(format!("Failed to bind TCP listener to {}", tcp_addr));
            }
        };

        // Tell the client that the tunnel is ready.
        let confirmed = match listener.local_addr() {
            Ok(bound_addr) => {
                confirm_client_configuration(&mut control_stream, bound_addr.port()).await
            }
            Err(err) => Err(err.into()),
        };
        if let Err(err) = confirmed {
            CloseCode::InternalError.close(&quic_conn, "failed to confirm configuration");
            return Err(err);
        }

        // Spawn the TCP listener in its own task.
        let tcp_config = Arc::clone(&config);
        let quic_conn_clone = quic_conn.clone();
        let cancel_token_clone = cancel_token.clone();
        tokio::spawn(async move {
            handle_tcp_listener(tcp_config, quic_conn_clone, listener, cancel_token_clone).await
        })
    };

    // 4. Run the control channel loop task.
    let end = run_control_channel_loop(control_stream, cancel_token).await;

    // Close the QUIC connection after the control channel finishes.
    debug!("Closing QUIC client connection from {}: {:?}", remote, end);
    let reason = match &end {
        ControlChannelEnd::Timeout => "keepalive timed out",
        ControlChannelEnd::UnexpectedMessage(_) => "unexpected control message",
        _ => "tunnel closed",
    };
    end.close_code().close(&quic_conn, reason);

    // Await the TCP listener task.
    debug!("Waiting for TCP listener task to finish");
    tcp_handle.await??;

    debug!("End of QUIC client connection from {}", remote);

    match end {
        ControlChannelEnd::Timeout => Err(anyhow!("keepalive timed out")),
        ControlChannelEnd::UnexpectedMessage(message) => Err(anyhow!(
            "unexpected control message {:?}",
            String::from_utf8_lossy(&message)
        )),
        _ => Ok(()),
    }
}
