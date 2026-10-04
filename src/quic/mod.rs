// PortRedirect QUIC Connection Module
//
// License: GPL-3.0-only

use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig};
use quinn::{TransportConfig, VarInt};
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info};

use crate::PortRedirectProtocol;

pub(crate) mod client;
pub(crate) mod fingerprint;
pub(crate) mod server;

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

/// How fast a side sends: the congestion controller of its QUIC connections, see
/// `--congestion-control`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CongestionControl {
    /// CUBIC, QUIC's and Linux TCP's usual one. It takes each lost packet for congestion.
    #[default]
    Cubic,
    /// BBR, which estimates the bandwidth and round-trip time instead, so packet loss for other
    /// reasons than congestion, e.g. on wireless links, slows it down far less. quinn marks its
    /// implementation experimental.
    Bbr,
}

impl CongestionControl {
    fn factory(self) -> Arc<dyn ControllerFactory + Send + Sync> {
        match self {
            CongestionControl::Cubic => Arc::new(CubicConfig::default()),
            CongestionControl::Bbr => Arc::new(BbrConfig::default()),
        }
    }
}

/// Sets the flow-control windows and the congestion controller, see `PortRedirectProtocol`.
fn configure_throughput(
    transport_config: &mut TransportConfig,
    receive_window: u32,
    congestion_control: CongestionControl,
) {
    transport_config.stream_receive_window(VarInt::from_u32(
        PortRedirectProtocol::QUIC_STREAM_RECEIVE_WINDOW,
    ));
    transport_config.receive_window(VarInt::from_u32(receive_window));
    transport_config.send_window(PortRedirectProtocol::QUIC_SEND_WINDOW);
    transport_config.congestion_controller_factory(congestion_control.factory());
}

/// Sets the server's transport settings.
pub fn configure_transport_config(
    transport_config: &mut TransportConfig,
    congestion_control: CongestionControl,
) {
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

    // The server reads no datagrams, so clients may not send any. Otherwise each connection
    // could buffer up to 1.25 MB of them, even before the client authenticates.
    transport_config.datagram_receive_buffer_size(None);

    // Small until the client has authenticated, see server::auth.
    configure_throughput(
        transport_config,
        PortRedirectProtocol::QUIC_UNAUTHENTICATED_RECEIVE_WINDOW,
        congestion_control,
    );
}

/// Returns the transport settings of the client.
///
/// The server opens one bidirectional stream for the control channel and one per forwarded
/// connection, so the client accepts `max_forwarded_connections + 1` concurrent streams.
pub fn client_transport_config(
    max_forwarded_connections: usize,
    congestion_control: CongestionControl,
) -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    let max_streams =
        u32::try_from(max_forwarded_connections.saturating_add(1)).unwrap_or(u32::MAX);
    transport_config.max_concurrent_bidi_streams(max_streams.into());
    transport_config.max_concurrent_uni_streams(0_u8.into());

    // Keep NAT mappings on the client's side alive, too.
    transport_config.keep_alive_interval(Some(PortRedirectProtocol::QUIC_KEEP_ALIVE_INTERVAL));
    transport_config.allow_spin(false);
    // The client reads no datagrams, so the server may not send any.
    transport_config.datagram_receive_buffer_size(None);
    configure_throughput(
        &mut transport_config,
        PortRedirectProtocol::QUIC_CONNECTION_RECEIVE_WINDOW,
        congestion_control,
    );
    transport_config
}

/// Binds a QUIC endpoint to `addr`: a server endpoint with `server_config`, else a client
/// endpoint. Its UDP socket has buffers of [`PortRedirectProtocol::UDP_SOCKET_BUFFER_SIZE`]
/// bytes, as far as the operating system allows.
pub fn bind_endpoint(
    addr: SocketAddr,
    server_config: Option<quinn::ServerConfig>,
) -> std::io::Result<quinn::Endpoint> {
    // Like quinn's own client endpoints, an IPv6 client endpoint also reaches IPv4 addresses.
    let dual_stack = server_config.is_none();
    let buffer_size = PortRedirectProtocol::UDP_SOCKET_BUFFER_SIZE;
    let socket = bind_udp_socket(addr, dual_stack, buffer_size)?;
    let runtime = Arc::new(quinn::TokioRuntime);
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        server_config,
        socket,
        runtime,
    )
}

/// Binds a UDP socket to `addr` and asks for buffers of `buffer_size` bytes. With `dual_stack`,
/// an IPv6 socket also sends to and receives from IPv4 addresses.
fn bind_udp_socket(
    addr: SocketAddr,
    dual_stack: bool,
    buffer_size: usize,
) -> std::io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if dual_stack && addr.is_ipv6() {
        if let Err(e) = socket.set_only_v6(false) {
            debug!("Can't make the UDP socket dual-stack: {}", e);
        }
    }
    // Smaller buffers only make losing datagrams likelier.
    let _ = socket.set_recv_buffer_size(buffer_size);
    let _ = socket.set_send_buffer_size(buffer_size);
    let (receive, send) = (socket.recv_buffer_size()?, socket.send_buffer_size()?);
    let sizes = format!(
        "{} KiB to receive, {} KiB to send",
        receive >> 10,
        send >> 10
    );
    debug!("UDP socket buffers: {}", sizes);
    if receive.min(send) < buffer_size {
        info!("{}", small_buffers_hint(&sizes, buffer_size));
    }
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Returns a hint to allow larger UDP socket buffers than the ones with `sizes`, which are
/// smaller than `requested`.
fn small_buffers_hint(sizes: &str, requested: usize) -> String {
    format!(
        "The UDP socket's buffers have {}, less than the {} KiB PortRedirect asks for, so datagrams that arrive in bursts may be lost, which slows down fast connections. On Linux, raise net.core.rmem_max and net.core.wmem_max, see docs/PERFORMANCE.md",
        sizes,
        requested >> 10
    )
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

    #[test]
    fn test_small_buffers_get_a_hint() {
        let hint = small_buffers_hint("416 KiB to receive, 416 KiB to send", 4 << 20);
        assert!(hint.contains("416 KiB to receive"), "{}", hint);
        assert!(hint.contains("4096 KiB PortRedirect asks for"), "{}", hint);
        assert!(hint.contains("net.core.rmem_max"), "{}", hint);
    }

    #[test]
    fn test_udp_sockets_get_larger_buffers() -> std::io::Result<()> {
        let default = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let default = socket2::SockRef::from(&default).recv_buffer_size()?;
        let requested = PortRedirectProtocol::UDP_SOCKET_BUFFER_SIZE;
        let socket = bind_udp_socket("127.0.0.1:0".parse().unwrap(), false, requested)?;
        let size = socket2::SockRef::from(&socket).recv_buffer_size()?;
        assert!(size >= default, "{} < {}", size, default);
        assert_ne!(socket.local_addr()?.port(), 0);

        // More than any operating system allows, which only gets a hint in the log.
        bind_udp_socket("127.0.0.1:0".parse().unwrap(), false, 1 << 30)?;
        Ok(())
    }

    #[test]
    fn test_ipv6_client_sockets_are_dual_stack() -> std::io::Result<()> {
        // Not every test machine has IPv6.
        let unspecified = "[::]:0".parse().unwrap();
        let Ok(socket) = bind_udp_socket(unspecified, true, 1 << 20) else {
            return Ok(());
        };
        assert!(!socket2::SockRef::from(&socket).only_v6()?);
        Ok(())
    }
}
