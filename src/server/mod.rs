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
