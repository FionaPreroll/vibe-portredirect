// PortRedirect Server
//
// License: GPL-3.0-only

pub(crate) mod auth;
pub(crate) mod client_handler;
pub(crate) mod clients;
pub(crate) mod config;
pub(crate) mod main;
pub(crate) mod metrics;
pub(crate) mod port_registry;
pub(crate) mod tcp_forwarder;
pub(crate) mod tcp_listener;

use std::str::FromStr;
use std::time::Duration;

use crate::PortRedirectProtocol;

/// Limits for the external TCP connections the server forwards for one client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardingLimits {
    /// Maximum number of concurrently forwarded connections. Further connections wait in the
    /// listen backlog until one ends.
    pub max_connections: usize,
    /// Maximum number of concurrently forwarded connections per external address (IPv6: per /64
    /// network), 0 for no limit. Further connections are closed right away.
    pub max_connections_per_ip: usize,
    /// Maximum number of new forwarded connections per second and external address, 0 for no
    /// limit, after `max_connection_burst_per_ip` at once. Further connections are closed right
    /// away.
    pub max_connection_rate_per_ip: u32,
    /// Number of new connections an external address may open at once, see
    /// `max_connection_rate_per_ip`.
    pub max_connection_burst_per_ip: u32,
    /// Forwarded connections are closed after this long without data transfer, if set.
    pub idle_timeout: Option<Duration>,
}

impl ForwardingLimits {
    pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 64;
    pub const DEFAULT_MAX_CONNECTION_RATE_PER_IP: u32 = 20;
    /// As many as the default allows at the same time.
    pub const DEFAULT_MAX_CONNECTION_BURST_PER_IP: u32 =
        Self::DEFAULT_MAX_CONNECTIONS_PER_IP as u32;
    pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
}

impl Default for ForwardingLimits {
    fn default() -> Self {
        Self {
            max_connections: PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS,
            max_connections_per_ip: Self::DEFAULT_MAX_CONNECTIONS_PER_IP,
            max_connection_rate_per_ip: Self::DEFAULT_MAX_CONNECTION_RATE_PER_IP,
            max_connection_burst_per_ip: Self::DEFAULT_MAX_CONNECTION_BURST_PER_IP,
            idle_timeout: Some(Self::DEFAULT_IDLE_TIMEOUT),
        }
    }
}

/// Represents a single port or a range of ports.
#[derive(Clone, Debug)]
pub enum PortSpec {
    Single(u16),
    Range(u16, u16),
}

impl FromStr for PortSpec {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some((start, end)) = s.split_once('-') {
            let start = parse_port(start, "start port")?;
            let end = parse_port(end, "end port")?;
            if start > end {
                return Err(format!("Invalid range: {}-{}", start, end));
            }
            Ok(PortSpec::Range(start, end))
        } else {
            Ok(PortSpec::Single(parse_port(s, "port")?))
        }
    }
}

/// Parses a port clients may request, see [`PortSpec::allows`] about port 0.
fn parse_port(s: &str, what: &str) -> Result<u16, String> {
    match s.trim().parse::<u16>() {
        Ok(0) => Err(format!(
            "Invalid {}: 0, the system would choose a random port",
            what
        )),
        Ok(port) => Ok(port),
        Err(e) => Err(format!("Invalid {}: {}", what, e)),
    }
}

// Check whether a port is allowed.
impl PortSpec {
    /// Returns true if the given port is allowed by this PortSpec.
    ///
    /// Port 0 is never allowed: listening on it makes the system choose a random port, which
    /// isn't necessarily allowed.
    pub fn allows(&self, port: u16) -> bool {
        port != 0
            && match self {
                PortSpec::Single(allowed) => port == *allowed,
                PortSpec::Range(start, end) => port >= *start && port <= *end,
            }
    }
}

/// Trait to check if a collection of PortSpec allows a given port.
pub trait AllowedPorts {
    /// Returns true if any `PortSpec` in the collection allows the given port.
    fn allows(&self, port: u16) -> bool;
}

impl AllowedPorts for [PortSpec] {
    fn allows(&self, port: u16) -> bool {
        self.iter().any(|spec| spec.allows(port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<PortSpec, String> {
        s.parse()
    }

    #[test]
    fn test_parse_single_ports_and_ranges() {
        assert!(matches!(parse("443"), Ok(PortSpec::Single(443))));
        assert!(matches!(parse(" 80 "), Ok(PortSpec::Single(80))));
        assert!(matches!(
            parse("1000-2000"),
            Ok(PortSpec::Range(1000, 2000))
        ));
        assert!(matches!(
            parse("1000 - 2000"),
            Ok(PortSpec::Range(1000, 2000))
        ));
        assert!(matches!(
            parse("8080-8080"),
            Ok(PortSpec::Range(8080, 8080))
        ));
        assert!(matches!(parse("1-65535"), Ok(PortSpec::Range(1, 65535))));
    }

    #[test]
    fn test_parse_rejects_invalid_specs() {
        for spec in [
            "",
            "-",
            "abc",
            "443-",
            "-443",
            "65536",
            "1-65536",
            "2000-1000",
            "1-2-3",
            "80,443",
            "-1",
        ] {
            assert!(parse(spec).is_err(), "{:?} must be rejected", spec);
        }
    }

    #[test]
    fn test_parse_rejects_port_zero() {
        for spec in ["0", "0-100", " 0 - 0 "] {
            let err = parse(spec).unwrap_err();
            assert!(err.contains("random port"), "{:?}: {}", spec, err);
        }
    }

    #[test]
    fn test_allows_range_boundaries() {
        let range = PortSpec::Range(1000, 2000);
        assert!(!range.allows(999));
        assert!(range.allows(1000));
        assert!(range.allows(2000));
        assert!(!range.allows(2001));

        let single = PortSpec::Single(443);
        assert!(single.allows(443));
        assert!(!single.allows(442) && !single.allows(444));
    }

    #[test]
    fn test_port_zero_is_never_allowed() {
        // Specs built in code are not parsed, so allows() must reject port 0 itself.
        assert!(!PortSpec::Single(0).allows(0));
        assert!(!PortSpec::Range(0, 100).allows(0));
        assert!(PortSpec::Range(0, 100).allows(1));
    }

    #[test]
    fn test_allowed_ports_of_a_list() {
        let allowed: Vec<PortSpec> = "80, 443,8000-8100"
            .split(',')
            .map(|spec| spec.parse().unwrap())
            .collect();
        for port in [80, 443, 8000, 8050, 8100] {
            assert!(allowed.allows(port), "{} must be allowed", port);
        }
        for port in [0, 81, 442, 7999, 8101] {
            assert!(!allowed.allows(port), "{} must not be allowed", port);
        }
        assert!(!Vec::<PortSpec>::new().allows(80));
    }
}
