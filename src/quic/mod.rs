// PortRedirect QUIC Connection Module
//
// License: GPL-3.0-only

use quinn::TransportConfig;

use crate::PortRedirectProtocol;

pub mod client;
pub mod server;

// QUIC ALPN field: port redirect protocol v4.
// Bump this whenever the protocol changes incompatibly (v2: LISTENPORT/LISTENING handshake,
// v3: mutual authentication bound to the TLS session and application close codes,
// v4: header at the start of each data stream).
pub const ALPN_QUIC_PORTREDIRECT: &[&[u8]] = &[b"pr-4"];

pub fn configure_transport_config(transport_config: &mut TransportConfig) {
    // QUIC connection advanced configuration

    // Schedule streams in a round-robin fashion
    transport_config.send_fairness(true);

    // We manage our own connection limit
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_concurrent_bidi_streams(0_u8.into());

    // 30s timeout is QUIC's default timeout
    transport_config.keep_alive_interval(Some(PortRedirectProtocol::QUIC_KEEP_ALIVE_INTERVAL));

    transport_config.crypto_buffer_size(crate::PortRedirectProtocol::QUIC_CRYPTO_BUFFER_SIZE);

    // We don't want to "sacrifice privacy" to more easily measure latency
    transport_config.allow_spin(false);
}

/// Returns the transport settings of the client.
///
/// The server opens one bidirectional stream for the control channel and one per forwarded
/// connection, so the client accepts `max_forwarded_connections + 1` concurrent streams.
pub fn client_transport_config(max_forwarded_connections: usize) -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    let max_streams =
        u32::try_from(max_forwarded_connections.saturating_add(1)).unwrap_or(u32::MAX);
    transport_config.max_concurrent_bidi_streams(max_streams.into());
    transport_config.max_concurrent_uni_streams(0_u8.into());

    // Keep NAT mappings on the client's side alive, too.
    transport_config.keep_alive_interval(Some(PortRedirectProtocol::QUIC_KEEP_ALIVE_INTERVAL));
    transport_config.allow_spin(false);
    transport_config
}
