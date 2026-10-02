// PortRedirect Server - Prometheus Metrics Printer (to console)
//
// License: GPL-3.0-only

use super::metrics_counters::*;

use chrono::Local;
use std::time::Duration;
use tokio::time::interval;

pub async fn print_metrics_loop() {
    let mut tick = interval(Duration::from_secs(1));
    let mut previous_metrics = String::new();

    loop {
        tick.tick().await;

        // Render the current metrics string without a timestamp.
        let current_metrics = format!(
            "accepted: {} | failed_accept: {} | quic_err: {} | bytes_a: {} | bytes_b: {} | tcp_quic_closed_err: {} | tcp_quic_closed_graceful: {} | keepalive_err: {} | server_opened: {} | server_closed: {}",
            TCP_CONNECTIONS_ACCEPTED.get(),
            TCP_CONNECTIONS_FAILED_ACCEPTING.get(),
            QUIC_DATA_STREAM_OPENING_ERRORS.get(),
            BYTES_TRANSMITTED_A.get(),
            BYTES_TRANSMITTED_B.get(),
            TCP_QUIC_CONNECTIONS_CLOSED_ERROR.get(),
            TCP_QUIC_CONNECTIONS_CLOSED_GRACEFUL.get(),
            KEEPALIVE_ERRORS.get(),
            SERVER_CONNECTIONS_OPENED_TOTAL.get(),
            SERVER_CONNECTIONS_GRACEFULLY_CLOSED_TOTAL.get()
        );

        // Print only if the metrics string has changed.
        if current_metrics != previous_metrics {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            eprintln!("{} | {}", timestamp, current_metrics);
            previous_metrics = current_metrics;
        }
    }
}
