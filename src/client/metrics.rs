// PortRedirect Client - Metrics
//
// The names are listed in the README. From 1.0 on, they are a compatibility promise: dashboards
// and alerts rely on them.
//
// License: GPL-3.0-only

use prometheus::{IntCounter, IntGauge, Registry};
use std::sync::LazyLock;

use crate::metrics::{counter, gauge};

/// Common prefix of the client's metric names.
pub const PREFIX: &str = "portredirect_client_";

/// The client's metrics.
pub static METRICS: LazyLock<ClientMetrics> = LazyLock::new(ClientMetrics::new);

/// The client's metrics, in a registry of their own.
pub struct ClientMetrics {
    pub registry: Registry,
    /// Attempts to connect to the server.
    pub connection_attempts: IntCounter,
    /// Tunnels set up: the client connected, authenticated and the server listens for it.
    pub tunnels: IntCounter,
    /// 1 while the tunnel is up, else 0.
    pub tunnel_up: IntGauge,
    /// Tunnels closed because the server didn't answer keepalive messages.
    pub keepalive_failures: IntCounter,
    /// Connections the server forwarded through the tunnel.
    pub forwarded_connections: IntCounter,
    /// Forwarded connections that are running.
    pub forwarded_connections_active: IntGauge,
    /// Forwarded connections that ended with an error, e.g. an abort.
    pub forwarded_connections_aborted: IntCounter,
    /// Forwarded connections for which the destination couldn't be reached.
    pub destination_connect_failures: IntCounter,
    /// Bytes sent to the destination.
    pub bytes_to_destination: IntCounter,
    /// Bytes received from the destination.
    pub bytes_from_destination: IntCounter,
}

impl ClientMetrics {
    fn new() -> Self {
        let registry = Registry::new();
        let counter = |name: &str, help: &str| counter(&registry, PREFIX, name, help);
        let gauge = |name: &str, help: &str| gauge(&registry, PREFIX, name, help);
        Self {
            connection_attempts: counter(
                "connection_attempts_total",
                "Attempts to connect to the server",
            ),
            tunnels: counter(
                "tunnels_total",
                "Tunnels set up: the client connected, authenticated and the server listens for it",
            ),
            tunnel_up: gauge("tunnel_up", "1 while the tunnel is up, else 0"),
            keepalive_failures: counter(
                "keepalive_failures_total",
                "Tunnels closed because the server didn't answer keepalive messages",
            ),
            forwarded_connections: counter(
                "forwarded_connections_total",
                "Connections the server forwarded through the tunnel",
            ),
            forwarded_connections_active: gauge(
                "forwarded_connections_active",
                "Forwarded connections that are running",
            ),
            forwarded_connections_aborted: counter(
                "forwarded_connections_aborted_total",
                "Forwarded connections that ended with an error, e.g. an abort",
            ),
            destination_connect_failures: counter(
                "destination_connect_failures_total",
                "Forwarded connections for which the destination couldn't be reached",
            ),
            bytes_to_destination: counter(
                "bytes_to_destination_total",
                "Bytes sent to the destination",
            ),
            bytes_from_destination: counter(
                "bytes_from_destination_total",
                "Bytes received from the destination",
            ),
            registry,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::summary;

    #[test]
    fn test_the_readme_lists_all_metrics() {
        let readme = include_str!("../../README.md");
        let metrics = ClientMetrics::new();
        for family in metrics.registry.gather() {
            let name = family.name().strip_prefix(PREFIX).unwrap();
            assert!(
                readme.contains(&format!("| `{}`", name)),
                "{} is missing in the README",
                name
            );
        }
    }

    #[test]
    fn test_all_metrics_are_listed_from_the_start() {
        let metrics = ClientMetrics::new();
        assert_eq!(
            summary(&metrics.registry, PREFIX),
            "bytes_from_destination_total: 0 | bytes_to_destination_total: 0 | connection_attempts_total: 0 | destination_connect_failures_total: 0 | forwarded_connections_aborted_total: 0 | forwarded_connections_active: 0 | forwarded_connections_total: 0 | keepalive_failures_total: 0 | tunnel_up: 0 | tunnels_total: 0"
        );
    }
}
