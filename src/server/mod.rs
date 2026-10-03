// PortRedirect Server
//
// License: GPL-3.0-only

pub mod auth;
pub mod client_handler;
pub mod metrics_counters;
pub mod metrics_printer;
pub mod tcp_forwarder;
pub mod tcp_listener;

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
    /// Forwarded connections are closed after this long without data transfer, if set.
    pub idle_timeout: Option<Duration>,
}

impl ForwardingLimits {
    pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 64;
    pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
}

impl Default for ForwardingLimits {
    fn default() -> Self {
        Self {
            max_connections: PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS,
            max_connections_per_ip: Self::DEFAULT_MAX_CONNECTIONS_PER_IP,
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
            let start = start
                .trim()
                .parse::<u16>()
                .map_err(|e| format!("Invalid start port: {}", e))?;
            let end = end
                .trim()
                .parse::<u16>()
                .map_err(|e| format!("Invalid end port: {}", e))?;
            if start > end {
                return Err(format!("Invalid range: {}-{}", start, end));
            }
            Ok(PortSpec::Range(start, end))
        } else {
            let port = s
                .parse::<u16>()
                .map_err(|e| format!("Invalid port: {}", e))?;
            Ok(PortSpec::Single(port))
        }
    }
}

// Check whether a port is allowed.
impl PortSpec {
    /// Returns true if the given port is allowed by this PortSpec.
    pub fn allows(&self, port: u16) -> bool {
        match self {
            PortSpec::Single(allowed) => port == *allowed,
            PortSpec::Range(start, end) => port >= *start && port <= *end,
        }
    }
}

/// Trait to check if a collection of PortSpec allows a given port.
pub trait AllowedPorts {
    /// Returns true if any `PortSpec` in the collection allows the given port.
    ///
    /// # Examples
    ///
    /// ```
    /// use portredirect::server::{PortSpec, AllowedPorts};
    ///
    /// let port = 12345;
    /// let allowed_ports: Vec<PortSpec> = vec![
    ///     PortSpec::Single(80),
    ///     PortSpec::Range(8000, 9000),
    ///     PortSpec::Single(12345),
    /// ];
    ///
    /// assert!(allowed_ports.allows(port));
    /// println!("Port {} is allowed.", port);
    /// ```
    fn allows(&self, port: u16) -> bool;
}

impl AllowedPorts for [PortSpec] {
    fn allows(&self, port: u16) -> bool {
        self.iter().any(|spec| spec.allows(port))
    }
}
