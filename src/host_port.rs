// PortRedirect - Hosts given by name or address, looked up when they are used
//
// License: GPL-3.0-only

use std::fmt;
use std::io;
use std::net::SocketAddr;

/// A host, given by name or address, and a port: the client's destination, the server it
/// connects to, or an address to listen on.
///
/// A name is looked up each time it is used, so the client follows changes of its addresses,
/// e.g. of a container that was created again, or of a server with a dynamic address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPort {
    host: String,
    port: u16,
}

impl HostPort {
    /// Returns the host and port. An IPv6 address may be in brackets, see [`unbracketed`].
    pub fn new(host: impl AsRef<str>, port: u16) -> Self {
        let host = unbracketed(host.as_ref()).to_string();
        Self { host, port }
    }

    /// Returns the host and the port, e.g. for `tokio::net::TcpStream::connect`, which looks up
    /// a name and tries each of its addresses.
    pub fn as_tuple(&self) -> (&str, u16) {
        (&self.host, self.port)
    }

    /// Looks up the addresses of a name, or returns the address the host is given by.
    pub async fn lookup(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host(self.as_tuple()).await?.collect())
    }

    /// Like [`HostPort::lookup`], but returns only the first address, e.g. to bind a socket to.
    pub async fn first_address(&self) -> io::Result<SocketAddr> {
        let no_address = || io::Error::new(io::ErrorKind::NotFound, "no address");
        self.lookup().await?.first().copied().ok_or_else(no_address)
    }
}

/// Returns `host` without the brackets around an IPv6 address, e.g. `::1` for `[::1]`, as URLs
/// and socket addresses write them. Names and addresses can't contain brackets otherwise.
pub fn unbracketed(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

impl From<SocketAddr> for HostPort {
    fn from(address: SocketAddr) -> Self {
        Self::new(address.ip().to_string(), address.port())
    }
}

impl fmt::Display for HostPort {
    /// Writes host:port, with an IPv6 address in brackets, like a socket address.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_addresses_may_be_in_brackets() {
        assert_eq!(unbracketed("[::1]"), "::1");
        assert_eq!(unbracketed("::1"), "::1");
        assert_eq!(unbracketed("[2001:db8::7]"), "2001:db8::7");
        // Only a pair of brackets around the whole host.
        assert_eq!(unbracketed("[::1"), "[::1");
        assert_eq!(unbracketed("[::1]:80"), "[::1]:80");
        assert_eq!(unbracketed("example.com"), "example.com");
        assert_eq!(HostPort::new("[::1]", 80), HostPort::new("::1", 80));
        assert_eq!(HostPort::new("[::1]", 80).to_string(), "[::1]:80");
        assert_eq!(HostPort::new("[::1]", 80).as_tuple(), ("::1", 80));
    }

    #[test]
    fn test_written_like_socket_addresses() {
        assert_eq!(HostPort::new("backend", 80).to_string(), "backend:80");
        for address in ["127.0.0.1:443", "[::1]:443"] {
            let address: SocketAddr = address.parse().unwrap();
            assert_eq!(HostPort::from(address).to_string(), address.to_string());
        }
    }

    #[tokio::test]
    async fn test_addresses_need_no_lookup() {
        for address in ["127.0.0.1:443", "[::1]:443"] {
            let address: SocketAddr = address.parse().unwrap();
            assert_eq!(HostPort::from(address).lookup().await.unwrap(), [address]);
            let first = HostPort::from(address).first_address().await.unwrap();
            assert_eq!(first, address);
        }
        let in_brackets = HostPort::new("[::1]", 443).first_address().await.unwrap();
        assert_eq!(in_brackets, "[::1]:443".parse().unwrap());
    }

    #[tokio::test]
    async fn test_names_are_looked_up() {
        let addresses = HostPort::new("localhost", 80).lookup().await.unwrap();
        assert!(
            addresses
                .iter()
                .all(|address| address.ip().is_loopback() && address.port() == 80),
            "{:?}",
            addresses
        );
        // The name is reserved for invalid names, RFC 2606.
        let invalid = HostPort::new("nonexistent.invalid", 80);
        assert!(invalid.lookup().await.is_err());
        assert!(invalid.first_address().await.is_err());
    }
}
