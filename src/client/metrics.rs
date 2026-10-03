// PortRedirect Client - Prometheus Metrics
// This module provides a Prometheus metrics endpoint and global counters for instrumentation.
//
// License: GPL-3.0-only

use anyhow::{Context, Result};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use prometheus::{Encoder, IntCounter, TextEncoder};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::metrics_helper::MetricsCounter;

/// Time a client gets to send the request headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Starts a metrics HTTP server on the given address.
///
/// The server exposes Prometheus metrics at the `/metrics` endpoint (HTTP/1.1 only).
/// This function runs the server indefinitely and only returns if binding fails.
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
/// # async fn run() -> anyhow::Result<()> {
///     let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
///     start_metrics_server(addr).await?;
/// #   Ok(())
/// # }
/// ```
pub async fn start_metrics_server(addr: impl Into<SocketAddr>) -> Result<()> {
    let addr = addr.into();
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics server to {}", addr))?;
    info!("Serving metrics on http://{}/metrics", addr);
    serve_metrics(listener).await
}

/// Serves the metrics endpoint on an already bound listener.
async fn serve_metrics(listener: TcpListener) -> Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(connection) => connection,
            Err(e) => {
                // Back off, e.g. if we ran out of file descriptors.
                warn!("Failed to accept metrics connection: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        tokio::spawn(async move {
            let service =
                service_fn(
                    |request| async move { Ok::<_, Infallible>(metrics_response(&request)) },
                );
            let result = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service)
                .await;
            if let Err(e) = result {
                debug!("Metrics connection from {} failed: {}", peer, e);
            }
        });
    }
}

/// Builds the response to a request for the metrics server.
///
/// `/metrics` gathers the Prometheus metrics and returns them in text format with the
/// appropriate `Content-Type` header, every other path is answered with 404.
fn metrics_response<B>(request: &Request<B>) -> Response<Full<Bytes>> {
    if request.uri().path() != "/metrics" {
        return plain_response(StatusCode::NOT_FOUND, "not found\n");
    }

    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        warn!("Failed to encode metrics: {}", e);
        return plain_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encode metrics\n",
        );
    }

    let mut response = Response::new(Full::new(Bytes::from(buffer)));
    if let Ok(content_type) = encoder.format_type().parse() {
        response.headers_mut().insert(CONTENT_TYPE, content_type);
    }
    response
}

fn plain_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *response.status_mut() = status;
    response
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
    use prometheus::register_int_counter;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Tests that the `/metrics` endpoint returns a valid response over HTTP.
    #[tokio::test]
    async fn test_metrics_endpoint() {
        // Register and increment the counter to produce some metrics data.
        let counter = register_int_counter!(
            "metrics_endpoint_test_total",
            "Counter registered by the metrics endpoint test"
        )
        .expect("Failed to register counter");
        counter.inc(); // Increment the counter so it appears in the metrics output.

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_metrics(listener));

        // Send a test request to the `/metrics` endpoint.
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        // Assert that the response status is OK.
        assert!(
            response.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected response: {}",
            response
        );

        // Assert that the Content-Type header is set correctly.
        let content_type = format!("content-type: {}\r\n", TextEncoder::new().format_type());
        assert!(
            response.to_lowercase().contains(&content_type),
            "Missing Content-Type header: {}",
            response
        );

        // Assert that the response body contains at least one known metric.
        assert!(
            response.contains("metrics_endpoint_test_total 1"),
            "Metrics output did not contain expected counter"
        );
    }

    /// Tests that other paths are not served.
    #[test]
    fn test_unknown_path_is_not_found() {
        let request = Request::builder().uri("/other").body(()).unwrap();
        assert_eq!(metrics_response(&request).status(), StatusCode::NOT_FOUND);
    }
}
