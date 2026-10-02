// PortRedirect QUIC Connection Module
//
// License: GPL-3.0-only

use quinn::TransportConfig;

pub mod client;
pub mod server;

// QUIC ALPN field: port redirect protocol v1
pub const ALPN_QUIC_PORTREDIRECT: &[&[u8]] = &[b"pr-1"];

pub fn configure_transport_config(transport_config: &mut TransportConfig) {
    // QUIC connection advanced configuration
    
    // Schedule streams in a round-robin fashion
    transport_config.send_fairness(true);

    // We manage our own connection limit
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_concurrent_bidi_streams(0_u8.into());

    // 30s timeout is QUIC's default timeout
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(25)));

    transport_config.crypto_buffer_size(crate::PortRedirectProtocol::QUIC_CRYPTO_BUFFER_SIZE);

    // We don't want to "sacrifice privacy" to more easily measure latency
    transport_config.allow_spin(false);
}
