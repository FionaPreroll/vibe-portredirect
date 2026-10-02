// PortRedirect Client - Prometheus Metrics Counters
//
// License: GPL-3.0-only

use prometheus::{register_int_counter, IntCounter};

// Global Prometheus counters. These are lazily initialized and can be used
// throughout the application.
lazy_static::lazy_static! {
    /// Total number of accepted connections.
    pub static ref CONNECTIONS_ACCEPTED: IntCounter =
        register_int_counter!(
            "connections_accepted_total",
            "Total number of accepted connections"
        ).expect("Failed to create connections_accepted_total counter");

    /// Total number of bytes transmitted for metric A.
    pub static ref BYTES_TRANSMITTED_A: IntCounter =
        register_int_counter!(
            "bytes_transmitted_a_total",
            "Total number of bytes transmitted for A"
        ).expect("Failed to create bytes_transmitted_a_total counter");

    /// Total number of bytes transmitted for metric B.
    pub static ref BYTES_TRANSMITTED_B: IntCounter =
        register_int_counter!(
            "bytes_transmitted_b_total",
            "Total number of bytes transmitted for B"
        ).expect("Failed to create bytes_transmitted_b_total counter");

    /// Total number of TCP forwarding errors encountered.
    pub static ref TCP_FORWARDING_ERRORS: IntCounter =
        register_int_counter!(
            "tcp_forwarding_errors_total",
            "Total number of TCP forwarding errors encountered"
        ).expect("Failed to create tcp_forwarding_errors_total counter");

    /// Total number of errors encountered in the keepalive loop.
    pub static ref KEEPALIVE_ERRORS: IntCounter =
        register_int_counter!(
            "keepalive_errors_total",
            "Total number of errors in the keepalive loop"
        ).expect("Failed to create keepalive_errors_total counter");

    /// Total number of times the client connected to the QUIC/PRRS server.
    pub static ref SERVER_CONNECTIONS_OPENED_TOTAL: IntCounter =
        register_int_counter!(
            "server_connections_opened_total",
            "Total number of times the client connected to the server"
        ).expect("Failed to create server_connections_opened_total counter");

    /// Total number of times the server connection was closed cleanly.
    pub static ref SERVER_CONNECTIONS_GRACEFULLY_CLOSED_TOTAL: IntCounter =
        register_int_counter!(
            "server_connections_gracefully_closed_total",
            "Total number of times the server connection was closed cleanly"
        ).expect("Failed to create server_connections_gracefully_closed_total counter");
}
