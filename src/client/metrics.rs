// PortRedirect Client - Prometheus Metrics
// This module provides a Prometheus metrics endpoint and global counters for instrumentation.
//
// License: GPL-3.0-only

use prometheus::{Encoder, IntCounter, TextEncoder};
use std::net::SocketAddr;
use warp::Filter;

use crate::metrics_helper::MetricsCounter;

/// Starts a metrics HTTP server on the given address.
///
/// The server exposes Prometheus metrics at the `/metrics` endpoint.
/// This function runs the server indefinitely.
///
/// # Arguments
///
/// * `addr` - The socket address to bind the server to. It can be any type that implements `Into<SocketAddr>`.
///
/// # Example
///
/// ```no_run 
/// use std::net::SocketAddr;
/// use portredirect::client::metrics::start_metrics_server;
///
/// # async fn run() {
///     let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
///     start_metrics_server(addr).await;
/// # }
/// ```
pub async fn start_metrics_server(addr: impl Into<SocketAddr>) {
    // Create the HTTP filter for the `/metrics` endpoint.
    let metrics_route = metrics_filter();

    // Start the Warp server with the metrics route.
    warp::serve(metrics_route).run(addr).await;
}

/// Constructs the Warp filter for the `/metrics` endpoint.
///
/// This filter gathers Prometheus metrics, encodes them in text format,
/// and returns an HTTP response with the appropriate `Content-Type` header.
///
/// # Panics
///
/// This filter will panic if encoding the metrics fails. Such a failure is
/// considered fatal and should not occur during normal operation.
fn metrics_filter() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("metrics").map(|| {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .expect("Failed to encode metrics");
        warp::reply::with_header(buffer, "Content-Type", encoder.format_type())
    })
}

/// Implementation of the `MetricsCounter` trait for `IntCounter`.
///
/// This implementation allows a Prometheus `IntCounter` to be incremented
/// by a specified amount using the `MetricsCounter` abstraction.
impl MetricsCounter for IntCounter {
    /// Increments the counter by the given `amount`.
    fn inc_by(&self, amount: u64) {
        // Call the inherent method on IntCounter from the Prometheus crate.
        prometheus::IntCounter::inc_by(self, amount);
    }
}

/// Implementation of the `MetricsCounter` trait for references to types that implement `MetricsCounter`.
///
/// This allows using a reference to a counter where a `MetricsCounter` is expected.
impl<T: MetricsCounter> MetricsCounter for &T {
    /// Increments the counter by the given `amount`.
    fn inc_by(&self, amount: u64) {
        (**self).inc_by(amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{register_int_counter, TextEncoder};
    use warp::http::StatusCode;

    /// Tests that the `/metrics` endpoint returns a valid response.
    #[tokio::test]
    async fn test_metrics_endpoint() {
        // Register and increment the counter to produce some metrics data.
        let counter = register_int_counter!(
            "connections_accepted_total",
            "Total number of connections accepted"
        )
        .expect("Failed to register counter");
        counter.inc(); // Increment the counter so it appears in the metrics output.

        // Create the filter.
        let filter = metrics_filter();

        // Send a test request to the `/metrics` endpoint.
        let response = warp::test::request().path("/metrics").reply(&filter).await;

        // Assert that the response status is OK.
        assert_eq!(response.status(), StatusCode::OK);

        // Assert that the Content-Type header is set correctly.
        let content_type = response
            .headers()
            .get("Content-Type")
            .expect("Missing Content-Type header")
            .to_str()
            .expect("Invalid Content-Type header");
        assert_eq!(content_type, TextEncoder::new().format_type());

        // Assert that the response body contains at least one known metric.
        let body = std::str::from_utf8(response.body()).expect("Response body is not valid UTF-8");
        assert!(
            body.contains("connections_accepted_total"),
            "Metrics output did not contain expected counter"
        );
    }
}
