// PortRedirect - IPv4 and IPv6 on the same socket
//
// License: GPL-3.0-only

use socket2::SockRef;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tracing::warn;

/// Returns `address` with an IPv4-mapped IPv6 address as the IPv4 address it contains, e.g.
/// `192.0.2.7:80` for `[::ffff:192.0.2.7]:80`, which is how a socket on `::` reports IPv4 peers.
pub fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// Returns whether `ip` is `::`, IPv6's address for any address.
pub fn is_any_ipv6(ip: IpAddr) -> bool {
    ip == IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

/// Makes `socket`, which is about to be bound to `address`, receive IPv4, too, if `address` is
/// `::`, as most systems do by default, but not all, e.g. Windows. On a system that can't, e.g.
/// OpenBSD, the socket only receives IPv6, and a warning says so.
pub fn receive_ipv4_on_any_ipv6(socket: SockRef<'_>, address: SocketAddr) {
    if is_any_ipv6(address.ip()) {
        if let Err(e) = socket.set_only_v6(false) {
            warn!(
                "The socket on {} only receives IPv6, not IPv4, too: {}",
                address, e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{collect_logs, ipv6_available};
    use socket2::{Domain, Protocol, Socket, Type};

    #[test]
    fn test_ipv4_mapped_addresses_are_written_as_ipv4() {
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:80".parse().unwrap();
        assert_eq!(canonical(mapped), "192.0.2.7:80".parse().unwrap());
        for address in ["192.0.2.7:80", "[2001:db8::7]:80", "[::1]:80"] {
            let address: SocketAddr = address.parse().unwrap();
            assert_eq!(canonical(address), address);
        }
    }

    #[test]
    fn test_sockets_on_any_ipv6_address_receive_ipv4_too() -> std::io::Result<()> {
        let any: SocketAddr = "[::]:0".parse().unwrap();
        let loopback: SocketAddr = "[::1]:0".parse().unwrap();
        if ipv6_available() {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_only_v6(true)?;
            receive_ipv4_on_any_ipv6(SockRef::from(&socket), any);
            assert!(!socket.only_v6()?);
            // A specific address only receives its own family anyway.
            socket.set_only_v6(true)?;
            receive_ipv4_on_any_ipv6(SockRef::from(&socket), loopback);
            assert!(socket.only_v6()?);
        }

        // E.g. on OpenBSD; an IPv4 socket can't either.
        let (logs, _logs) = collect_logs("warn");
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        receive_ipv4_on_any_ipv6(SockRef::from(&socket), any);
        let warnings = logs.lines();
        assert_eq!(warnings.len(), 1, "{:?}", warnings);
        assert!(
            warnings[0].contains("The socket on [::]:0 only receives IPv6, not IPv4, too: "),
            "{:?}",
            warnings
        );
        Ok(())
    }
}
