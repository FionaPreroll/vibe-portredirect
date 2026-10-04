// PortRedirect Server - QUIC client handler
//
// License: GPL-3.0-only

use crate::metrics::Active;
use crate::protocol::auth::ClientName;
use crate::protocol::close::CloseCode;
use crate::protocol::control::{receive_hello, send_welcome, Greeting, SERVER_SOFTWARE};
use crate::protocol::keepalive::{run_control_channel_loop, ControlChannelEnd};
use crate::quic::server::ServerConfig;
use crate::quic::ProtocolVersion;
use crate::server::metrics::METRICS;
use crate::server::port_registry::PortTaken;
use crate::server::AllowedPorts;
use crate::PortRedirectProtocol;
use crate::{app_data::ServerAppData, server::tcp_listener::handle_tcp_listener};

use super::auth::authenticate_quic_client;

use anyhow::{anyhow, bail, Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, info_span, Instrument};

// Handles one PR QUIC client connection.
// Called by run_quic_server.
#[cfg_attr(not(coverage), tracing::instrument(skip(config, quic_conn)))]
pub async fn handle_quic_client_connection(
    config: Arc<ServerConfig<ServerAppData>>,
    quic_conn: quinn::Connection,
) -> Result<()> {
    let remote = quic_conn.remote_address();
    debug!("Handling QUIC client connection from {}", remote);

    // QUIC requires the TLS handshake to agree on one of the protocol versions we offer (ALPN).
    // Each version has its own handler; so far there is only one.
    match ProtocolVersion::of(&quic_conn).context("no protocol version negotiated")? {
        ProtocolVersion::V5 => {}
    }

    // 1. Authenticate client. On failure, the connection is closed already.
    let (control_stream, client) =
        match authenticate_quic_client(Arc::clone(&config), quic_conn.clone()).await {
            Ok(authenticated) => {
                // Auth succeeded. Continue with the control stream.
                config.admission.record_success(remote.ip());
                authenticated
            }
            Err(err) => {
                config.admission.record_failure(remote.ip());
                METRICS.authentication_failures.inc();
                return Err(err).context(format!(
                    "failed to authenticate PR QUIC client from {}",
                    remote
                ));
            }
        };

    // From now on, all log messages of this connection name the client.
    let span = info_span!("tunnel", client = client.name.as_str());
    serve_client(config, quic_conn, control_stream, client.name)
        .instrument(span)
        .await
}

/// Sets up the tunnel for an authenticated client and keeps it up until the connection ends.
pub(crate) async fn serve_client<S>(
    config: Arc<ServerConfig<ServerAppData>>,
    quic_conn: quinn::Connection,
    mut control_stream: S,
    client: ClientName,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let remote = quic_conn.remote_address();

    // 2. Receive the client's HELLO.
    let hello = match timeout(
        PortRedirectProtocol::CONFIGURATION_TIMEOUT,
        receive_hello(&mut control_stream),
    )
    .await
    {
        Ok(Ok(hello)) => hello,
        Ok(Err(err)) => {
            CloseCode::ProtocolViolation.close(&quic_conn, "invalid HELLO");
            return Err(err).context(format!("failed to receive HELLO from {}", remote));
        }
        Err(_) => {
            CloseCode::ConfigurationTimeout.close(&quic_conn, "configuration timed out");
            return Err(anyhow!("configuration timed out"))
                .context(format!("configuration timeout from {}", remote));
        }
    };
    let port = hello.listen_port;
    // The software is text from the client, so it is logged escaped.
    info!(
        "Client {:?} ({:?}) from {} asks for port {}",
        client.as_str(),
        hello.software(),
        remote,
        port
    );

    // Validate that the client may use the requested port.
    let allowed = config
        .app_data
        .clients
        .get(&client)
        .is_some_and(|entry| entry.ports.allows(port));
    if !allowed {
        CloseCode::PortNotAllowed.close(&quic_conn, "port not allowed");
        bail!("client {:?} may not use port {}", client.as_str(), port);
    }

    // 3. Take the port, replacing an older connection of the same client.
    let lease = match config
        .app_data
        .ports
        .acquire(port, &client, &quic_conn)
        .await
    {
        Ok(lease) => lease,
        Err(taken) => {
            if let PortTaken::ByOtherClient(holder) = &taken {
                debug!(
                    "Client {:?} waits as standby for port {}, which client {:?} holds",
                    client.as_str(),
                    port,
                    holder.as_str()
                );
            }
            CloseCode::PortUnavailable.close(&quic_conn, "port in use");
            return Err(taken).context(format!("port {} is not available", port));
        }
    };

    // 4. Create the TCP listener.
    let tcp_addr = format!("{}:{}", config.app_data.local_bind_ip, port);
    let listener = match TcpListener::bind(&tcp_addr).await {
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
            send_welcome(
                &mut control_stream,
                &Greeting::new(SERVER_SOFTWARE, bound_addr.port()),
            )
            .await
        }
        Err(err) => Err(err.into()),
    };
    if let Err(err) = confirmed {
        CloseCode::InternalError.close(&quic_conn, "failed to confirm configuration");
        return Err(err);
    }
    let metrics = METRICS.client(&client);
    metrics.tunnels.inc();
    let _tunnel_active = Active::new(&metrics.tunnels_active);

    // Spawn the TCP listener in its own task. It releases the port when it ends: when the
    // client sends DRAIN or the connection ends.
    let listener_token = CancellationToken::new();
    let tcp_handle = tokio::spawn(
        handle_tcp_listener(
            Arc::clone(&config),
            quic_conn.clone(),
            listener,
            lease,
            metrics.clone(),
            listener_token.clone(),
        )
        .in_current_span(),
    );

    // 5. Run the control channel loop.
    let end =
        run_control_channel_loop(&mut control_stream, listener_token, config.shutdown.clone())
            .await;

    // Close the QUIC connection after the control channel finishes, and only then end the
    // control stream: the client could read its end before the reason, e.g. an unexpected
    // message, and take it for a failed keepalive.
    debug!("Closing QUIC client connection from {}: {:?}", remote, end);
    let reason = match &end {
        ControlChannelEnd::Timeout => "keepalive timed out",
        ControlChannelEnd::ProtocolViolation(_) => "unexpected control message",
        ControlChannelEnd::StreamClosed(_) => "tunnel closed",
    };
    end.close_code().close(&quic_conn, reason);
    drop(control_stream);
    if end.close_code() == CloseCode::KeepaliveFailed {
        metrics.keepalive_failures.inc();
    }

    // Await the TCP listener task. It is only cancelled when the runtime shuts down at the end
    // of the program, which is no error of this connection.
    debug!("Waiting for TCP listener task to finish");
    match tcp_handle.await {
        Ok(result) => result?,
        Err(e) if e.is_cancelled() => debug!("TCP listener task cancelled"),
        Err(e) => return Err(e.into()),
    }
    debug!("End of QUIC client connection from {}", remote);

    match end {
        ControlChannelEnd::Timeout => Err(anyhow!("keepalive timed out")),
        ControlChannelEnd::ProtocolViolation(violation) => Err(anyhow!(violation)),
        ControlChannelEnd::StreamClosed(_) => Ok(()),
    }
}
