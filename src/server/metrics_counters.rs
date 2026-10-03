// PortRedirect Server - Prometheus Metrics Counters
//
// License: GPL-3.0-only

use prometheus::{register_int_counter, IntCounter};

// Global Prometheus counters. These are lazily initialized and can be used
// throughout the application.
// The names are prefixed so they don't collide with the client's counters when both
// run in the same process (e.g. in integration tests), as they share the default registry.
lazy_static::lazy_static! {
    pub static ref TCP_CONNECTIONS_ACCEPTED: IntCounter =
        register_int_counter!(
            "portredirect_server_tcp_connections_accepted_total",
            "Total number of accepted TCP connections"
        ).expect("Failed to create counter");

    pub static ref TCP_CONNECTIONS_FAILED_ACCEPTING: IntCounter =
    register_int_counter!(
        "portredirect_server_tcp_connections_failed_accepting_total",
        "Total number of failures accepting TCP connections"
    ).expect("Failed to create counter");

    pub static ref TCP_CONNECTIONS_REFUSED: IntCounter =
    register_int_counter!(
        "portredirect_server_tcp_connections_refused_total",
        "Total number of TCP connections closed right away, as their address had too many connections"
    ).expect("Failed to create counter");

    pub static ref QUIC_DATA_STREAM_OPENING_ERRORS: IntCounter =
    register_int_counter!(
        "portredirect_server_quic_data_stream_opening_errors_total",
        "Total number of errors opening QUIC bidirectional data streams"
    ).expect("Failed to create counter");

    /// Total number of bytes transmitted for metric A.
    pub static ref BYTES_TRANSMITTED_A: IntCounter =
        register_int_counter!(
            "portredirect_server_bytes_transmitted_a_total",
            "Total number of bytes transmitted for A"
        ).expect("Failed to create counter");

    /// Total number of bytes transmitted for metric B.
    pub static ref BYTES_TRANSMITTED_B: IntCounter =
        register_int_counter!(
            "portredirect_server_bytes_transmitted_b_total",
            "Total number of bytes transmitted for B"
        ).expect("Failed to create bytes_transmitted_b_total counter");

    /// Total number of TCP forwarding errors encountered.
    pub static ref TCP_QUIC_CONNECTIONS_CLOSED_ERROR: IntCounter =
        register_int_counter!(
            "portredirect_server_tcp_quic_connections_closed_error_total",
            "Total number of TCP/QUIC forwarding closing errors encountered"
        ).expect("Failed to create tcp_forwarding_errors_total counter");

    pub static ref TCP_QUIC_CONNECTIONS_CLOSED_GRACEFUL: IntCounter =
        register_int_counter!(
            "portredirect_server_tcp_quic_connections_closed_graceful_total",
            "Total number of gracefully completed QUIC/TCP forwardings."
        ).expect("Failed to create counter");

    /// Total number of client connections closed because no keepalive message arrived in time.
    pub static ref KEEPALIVE_ERRORS: IntCounter =
        register_int_counter!(
            "portredirect_server_keepalive_errors_total",
            "Total number of client connections closed because no keepalive message arrived in time"
        ).expect("Failed to create keepalive_errors_total counter");

    /// Total number of client connections that authenticated successfully.
    pub static ref CLIENT_CONNECTIONS_TOTAL: IntCounter =
        register_int_counter!(
            "portredirect_server_client_connections_total",
            "Total number of client connections that authenticated successfully"
        ).expect("Failed to create client_connections_total counter");

    /// Total number of authenticated client connections that ended normally.
    pub static ref CLIENT_CONNECTIONS_CLOSED_TOTAL: IntCounter =
        register_int_counter!(
            "portredirect_server_client_connections_closed_total",
            "Total number of authenticated client connections that ended normally"
        ).expect("Failed to create client_connections_closed_total counter");
}
