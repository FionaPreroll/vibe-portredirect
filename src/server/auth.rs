// PortRedirect Server - Authenticate client to server
//
// License: GPL-3.0-only

use crate::protocol::auth::{server_authenticate, session_binding};
use crate::protocol::close::CloseCode;
use crate::quic::server::{raise_receive_window, ServerConfig};
use crate::server::clients::Credentials;
use crate::PortRedirectProtocol;
use crate::{app_data::ServerAppData, bi_stream::BiStream};

use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use tokio::time::timeout;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use tracing::{debug, info};

/// The control stream of a connection, as the server sees it.
pub type ControlStream = BiStream<Compat<quinn::RecvStream>, Compat<quinn::SendStream>>;

/// Opens the control stream, which stays open for the lifetime of the connection, and
/// authenticates the client over it: verifies that the client knows the PSK of the client it
/// names and proves that we know it, too. Returns the client's name and that PSK.
///
/// If that fails or takes too long, closes the connection with the reason and fails. The caller
/// logs the error.
#[cfg_attr(not(coverage), tracing::instrument(skip(config, conn)))]
pub async fn authenticate_quic_client(
    config: Arc<ServerConfig<ServerAppData>>,
    conn: quinn::Connection,
) -> Result<(ControlStream, Credentials)> {
    debug!("Authenticating PR QUIC client");

    // The control stream must outlive the closing of the connection: dropping a stream ends it,
    // and the client could read that end before the reason, e.g. a rejected PSK, and take it for
    // a temporary failure. So it is kept here, outside the timed authentication.
    let mut control_stream = None;
    let authenticated = timeout(
        PortRedirectProtocol::AUTHENTICATION_TIMEOUT,
        authenticate(&config, &conn, &mut control_stream),
    )
    .await;
    let (client, psk_index, psk_count) = match authenticated {
        Ok(Ok(authenticated)) => authenticated,
        Ok(Err(e)) => {
            CloseCode::AuthenticationFailed.close(&conn, "authentication failed");
            return Err(e);
        }
        Err(_) => {
            CloseCode::AuthenticationTimeout.close(&conn, "authentication timed out");
            return Err(anyhow!("authentication timed out"));
        }
    };
    let control_stream = control_stream.context("authenticated without a control stream")?;
    // Until now, the client could only send a little.
    raise_receive_window(&conn);
    let name = client.name.as_str();
    if psk_count > 1 {
        let psk = psk_index + 1;
        info!(
            "Authenticated client {:?} with PSK {} of {}",
            name, psk, psk_count
        );
    } else {
        info!("Authenticated client {:?}", name);
    }

    Ok((control_stream, client))
}

/// Opens the control stream into `control_stream` and authenticates the client over it, with the
/// clients of the current settings. Returns the client's credentials, which of its PSKs it used,
/// starting at 0, and how many it has.
async fn authenticate(
    config: &ServerConfig<ServerAppData>,
    conn: &quinn::Connection,
    control_stream: &mut Option<ControlStream>,
) -> Result<(Credentials, usize, usize)> {
    let (send, recv) = conn
        .open_bi()
        .await
        .context("failed to open the control stream")?;
    let stream_id = recv.id();
    debug!("opened control channel with stream id {}", stream_id);

    // Convert the futures-based Quinn streams into Tokio-compatible streams.
    let control_stream = control_stream.insert(BiStream::new(
        recv.compat(),
        send.compat_write(),
        stream_id.to_string(),
    ));
    let binding = session_binding(conn)?;
    // The same clients for the whole authentication, even if a reload changes them meanwhile.
    let settings = config.app_data.settings();
    let client = server_authenticate(control_stream, &settings.clients, &binding).await?;
    let psks = &settings
        .clients
        .get(&client.name)
        .context("authenticated a client that isn't listed")?
        .psks;
    let credentials = Credentials {
        psk: psks[client.psk_index].clone(),
        name: client.name,
    };
    Ok((credentials, client.psk_index, psks.len()))
}
