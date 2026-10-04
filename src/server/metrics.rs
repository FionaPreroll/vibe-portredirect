// PortRedirect Server - Metrics
//
// The names are listed in the README. From 1.0 on, they are a compatibility promise: dashboards
// and alerts rely on them. Metrics of authenticated clients carry the client's name as label
// `client`; names are configured, so there are few of them.
//
// License: GPL-3.0-only

use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Registry};
use std::sync::LazyLock;

use crate::metrics::{counter, counter_vec, gauge_vec};
use crate::protocol::auth::ClientName;

/// Common prefix of the server's metric names.
pub const PREFIX: &str = "portredirect_server_";

/// The server's metrics.
pub static METRICS: LazyLock<ServerMetrics> = LazyLock::new(ServerMetrics::new);

/// Why the server refused a QUIC connection, the label `reason` of
/// [`ServerMetrics::quic_connections_refused`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    /// The address is blocked after failed attempts.
    Blocked,
    /// The server has as many QUIC connections as allowed.
    ConnectionLimit,
    /// The address has as many QUIC connections as allowed.
    AddressLimit,
    /// The server shuts down.
    ShuttingDown,
}

impl RefusalReason {
    const ALL: [RefusalReason; 4] = [
        RefusalReason::Blocked,
        RefusalReason::ConnectionLimit,
        RefusalReason::AddressLimit,
        RefusalReason::ShuttingDown,
    ];

    fn label(self) -> &'static str {
        match self {
            RefusalReason::Blocked => "blocked",
            RefusalReason::ConnectionLimit => "connection_limit",
            RefusalReason::AddressLimit => "address_limit",
            RefusalReason::ShuttingDown => "shutting_down",
        }
    }
}

/// The server's metrics, in a registry of their own.
pub struct ServerMetrics {
    pub registry: Registry,
    quic_connections_refused: IntCounterVec,
    /// Failed TLS handshakes and authentication attempts, which count towards blocking an
    /// address.
    pub authentication_failures: IntCounter,
    tunnels: IntCounterVec,
    tunnels_active: IntGaugeVec,
    keepalive_failures: IntCounterVec,
    forwarded_connections: IntCounterVec,
    forwarded_connections_active: IntGaugeVec,
    forwarded_connections_refused: IntCounterVec,
    forwarded_connections_failed: IntCounterVec,
    forwarded_connections_aborted: IntCounterVec,
    accept_errors: IntCounterVec,
    bytes_from_external: IntCounterVec,
    bytes_to_external: IntCounterVec,
}

impl ServerMetrics {
    fn new() -> Self {
        let registry = Registry::new();
        let by_client =
            |name: &str, help: &str| counter_vec(&registry, PREFIX, name, help, &["client"]);
        let metrics = Self {
            quic_connections_refused: counter_vec(
                &registry,
                PREFIX,
                "quic_connections_refused_total",
                "QUIC connections refused before the TLS handshake, by reason",
                &["reason"],
            ),
            authentication_failures: counter(
                &registry,
                PREFIX,
                "authentication_failures_total",
                "Failed TLS handshakes and authentication attempts, which count towards blocking an address",
            ),
            tunnels: by_client(
                "tunnels_total",
                "Tunnels set up: the client authenticated and the server listens for it",
            ),
            tunnels_active: gauge_vec(
                &registry,
                PREFIX,
                "tunnels_active",
                "Tunnels that are up",
                &["client"],
            ),
            keepalive_failures: by_client(
                "keepalive_failures_total",
                "Tunnels closed because no keepalive message arrived in time",
            ),
            forwarded_connections: by_client(
                "forwarded_connections_total",
                "External connections forwarded through the tunnel",
            ),
            forwarded_connections_active: gauge_vec(
                &registry,
                PREFIX,
                "forwarded_connections_active",
                "Forwarded connections that are running",
                &["client"],
            ),
            forwarded_connections_refused: counter_vec(
                &registry,
                PREFIX,
                "forwarded_connections_refused_total",
                "External connections closed right away, as their address had too many connections or opened them too fast, by reason",
                &["client", "reason"],
            ),
            forwarded_connections_failed: by_client(
                "forwarded_connections_failed_total",
                "External connections that couldn't be forwarded, as the client accepted no stream for them",
            ),
            forwarded_connections_aborted: by_client(
                "forwarded_connections_aborted_total",
                "Forwarded connections that ended with an error, e.g. an abort",
            ),
            accept_errors: by_client(
                "accept_errors_total",
                "Failures to accept an external connection, e.g. for lack of file descriptors",
            ),
            bytes_from_external: by_client(
                "bytes_from_external_total",
                "Bytes received from external connections",
            ),
            bytes_to_external: by_client(
                "bytes_to_external_total",
                "Bytes sent to external connections",
            ),
            registry,
        };
        for reason in RefusalReason::ALL {
            metrics
                .quic_connections_refused
                .with_label_values(&[reason.label()]);
        }
        metrics
    }

    /// Counts a QUIC connection refused for `reason`.
    pub fn refused(&self, reason: RefusalReason) {
        self.quic_connections_refused
            .with_label_values(&[reason.label()])
            .inc();
    }

    /// Returns the metrics of the client named `client`, which are listed from now on, e.g. with
    /// 0 before the client connected.
    pub fn client(&self, client: &ClientName) -> ClientMetrics {
        let label = [client.as_str()];
        let refused = |reason: &str| {
            self.forwarded_connections_refused
                .with_label_values(&[client.as_str(), reason])
        };
        ClientMetrics {
            tunnels: self.tunnels.with_label_values(&label),
            tunnels_active: self.tunnels_active.with_label_values(&label),
            keepalive_failures: self.keepalive_failures.with_label_values(&label),
            forwarded_connections: self.forwarded_connections.with_label_values(&label),
            forwarded_connections_active: self
                .forwarded_connections_active
                .with_label_values(&label),
            forwarded_connections_refused: RefusedConnections {
                address_limit: refused("address_limit"),
                rate_limit: refused("rate_limit"),
            },
            forwarded_connections_failed: self
                .forwarded_connections_failed
                .with_label_values(&label),
            forwarded_connections_aborted: self
                .forwarded_connections_aborted
                .with_label_values(&label),
            accept_errors: self.accept_errors.with_label_values(&label),
            bytes_from_external: self.bytes_from_external.with_label_values(&label),
            bytes_to_external: self.bytes_to_external.with_label_values(&label),
        }
    }
}

/// The server's metrics of one client, see [`ServerMetrics`] for their meaning.
#[derive(Clone, Debug)]
pub struct ClientMetrics {
    pub tunnels: IntCounter,
    pub tunnels_active: IntGauge,
    pub keepalive_failures: IntCounter,
    pub forwarded_connections: IntCounter,
    pub forwarded_connections_active: IntGauge,
    pub forwarded_connections_refused: RefusedConnections,
    pub forwarded_connections_failed: IntCounter,
    pub forwarded_connections_aborted: IntCounter,
    pub accept_errors: IntCounter,
    pub bytes_from_external: IntCounter,
    pub bytes_to_external: IntCounter,
}

/// External connections the server closed right away, by the label `reason`.
#[derive(Clone, Debug)]
pub struct RefusedConnections {
    /// The address had as many connections as allowed.
    pub address_limit: IntCounter,
    /// The address opened new connections faster than allowed.
    pub rate_limit: IntCounter,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::summary;

    #[test]
    fn test_the_readme_lists_all_metrics() {
        let readme = include_str!("../../README.md");
        let metrics = ServerMetrics::new();
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
    fn test_metrics_of_known_clients_are_listed_from_the_start() {
        let metrics = ServerMetrics::new();
        let home = metrics.client(&"home".parse().unwrap());
        metrics.client(&"office".parse().unwrap());
        home.forwarded_connections.inc();
        home.forwarded_connections_refused.rate_limit.inc();
        metrics.refused(RefusalReason::Blocked);

        assert_eq!(
            summary(&metrics.registry, PREFIX),
            "accept_errors_total: 0 | authentication_failures_total: 0 | bytes_from_external_total: 0 | bytes_to_external_total: 0 | forwarded_connections_aborted_total: 0 | forwarded_connections_active: 0 | forwarded_connections_failed_total: 0 | forwarded_connections_refused_total: 1 | forwarded_connections_total: 1 | keepalive_failures_total: 0 | quic_connections_refused_total: 1 | tunnels_active: 0 | tunnels_total: 0"
        );

        let mut text = Vec::new();
        prometheus::Encoder::encode(
            &prometheus::TextEncoder::new(),
            &metrics.registry.gather(),
            &mut text,
        )
        .unwrap();
        let text = String::from_utf8(text).unwrap();
        for line in [
            "portredirect_server_forwarded_connections_total{client=\"home\"} 1\n",
            "portredirect_server_forwarded_connections_total{client=\"office\"} 0\n",
            "portredirect_server_forwarded_connections_refused_total{client=\"home\",reason=\"rate_limit\"} 1\n",
            "portredirect_server_forwarded_connections_refused_total{client=\"office\",reason=\"address_limit\"} 0\n",
            "portredirect_server_quic_connections_refused_total{reason=\"blocked\"} 1\n",
            "portredirect_server_quic_connections_refused_total{reason=\"shutting_down\"} 0\n",
        ] {
            assert!(text.contains(line), "no {:?} in:\n{}", line, text);
        }
    }
}
