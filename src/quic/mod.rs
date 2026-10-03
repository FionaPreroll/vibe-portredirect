// PortRedirect QUIC Connection Module
//
// License: GPL-3.0-only

use quinn::TransportConfig;

use crate::PortRedirectProtocol;

pub mod client;
pub mod server;

// QUIC ALPN field: the protocol versions this program speaks, see ProtocolVersion.
pub const ALPN_QUIC_PORTREDIRECT: &[&[u8]] = &[b"pr-5"];

/// The protocol versions this program speaks, each identified by its ALPN.
///
/// Every incompatible protocol change gets a new version (v2: LISTENPORT/LISTENING handshake,
/// v3: mutual authentication bound to the TLS session and application close codes, v4: header at
/// the start of each data stream, v5: framed messages with parameters, client names and aborted
/// data streams). A server that speaks several versions handles each connection according to
/// the negotiated one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// Version 5 (`pr-5`), see docs/PROTOCOL.md.
    V5,
}

impl ProtocolVersion {
    pub const ALL: [ProtocolVersion; 1] = [ProtocolVersion::V5];

    /// Returns the ALPN identifier of this version.
    pub fn alpn(self) -> &'static [u8] {
        match self {
            ProtocolVersion::V5 => b"pr-5",
        }
    }

    /// Returns the version with the ALPN identifier `alpn`, if this program speaks it.
    pub fn from_alpn(alpn: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|version| version.alpn() == alpn)
    }

    /// Returns the version negotiated in the TLS handshake of `connection`. QUIC requires a
    /// negotiated version, so the handshake fails without one.
    pub fn of(connection: &quinn::Connection) -> Option<Self> {
        let handshake_data = connection
            .handshake_data()?
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .ok()?;
        Self::from_alpn(handshake_data.protocol.as_deref()?)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_lists_all_versions() {
        let alpns: Vec<&[u8]> = ProtocolVersion::ALL.iter().map(|v| v.alpn()).collect();
        assert_eq!(alpns, ALPN_QUIC_PORTREDIRECT);
        assert_eq!(
            ProtocolVersion::from_alpn(b"pr-5"),
            Some(ProtocolVersion::V5)
        );
        assert_eq!(ProtocolVersion::from_alpn(b"pr-4"), None);
    }
}
