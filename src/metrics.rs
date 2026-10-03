// PortRedirect - Metrics shared by server and client: the Prometheus endpoint and helpers
//
// Each program keeps its metrics in a registry of its own, see client::metrics and
// server::metrics, so they are listed from the start, with 0, and don't mix when both run in
// one process, e.g. in tests.
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
use prometheus::core::Collector;
use prometheus::proto::MetricType;
use prometheus::{
    Encoder, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

/// Time a client gets to send the request headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause after a failure to accept a connection, e.g. when running out of file descriptors.
const ACCEPT_ERROR_DELAY: Duration = Duration::from_millis(100);

/// Registers `metric` in `registry` and returns it.
///
/// Panics if a metric of the same name is registered already: the names are fixed.
fn register<M: Collector + Clone + 'static>(registry: &Registry, metric: M) -> M {
    registry
        .register(Box::new(metric.clone()))
        .expect("duplicate metric name");
    metric
}

/// Returns a new counter `{prefix}{name}`, registered in `registry`.
pub fn counter(registry: &Registry, prefix: &str, name: &str, help: &str) -> IntCounter {
    let metric = IntCounter::with_opts(Opts::new(format!("{}{}", prefix, name), help))
        .expect("invalid metric");
    register(registry, metric)
}

/// Returns a new gauge `{prefix}{name}`, registered in `registry`.
pub fn gauge(registry: &Registry, prefix: &str, name: &str, help: &str) -> IntGauge {
    let metric = IntGauge::with_opts(Opts::new(format!("{}{}", prefix, name), help))
        .expect("invalid metric");
    register(registry, metric)
}

/// Returns new counters `{prefix}{name}` with `labels`, registered in `registry`.
pub fn counter_vec(
    registry: &Registry,
    prefix: &str,
    name: &str,
    help: &str,
    labels: &[&str],
) -> IntCounterVec {
    let metric = IntCounterVec::new(Opts::new(format!("{}{}", prefix, name), help), labels)
        .expect("invalid metric");
    register(registry, metric)
}

/// Returns new gauges `{prefix}{name}` with `labels`, registered in `registry`.
pub fn gauge_vec(
    registry: &Registry,
    prefix: &str,
    name: &str,
    help: &str,
    labels: &[&str],
) -> IntGaugeVec {
    let metric = IntGaugeVec::new(Opts::new(format!("{}{}", prefix, name), help), labels)
        .expect("invalid metric");
    register(registry, metric)
}

/// Increments a gauge while it lives, e.g. the running connections while one runs.
pub struct Active(IntGauge);

impl Active {
    pub fn new(gauge: &IntGauge) -> Self {
        gauge.inc();
        Self(gauge.clone())
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// A counter that forwarding increments by the bytes it transfers.
pub trait MetricsCounter {
    /// Increment the counter by a given amount.
    fn inc_by(&self, amount: u64);
}

impl MetricsCounter for IntCounter {
    fn inc_by(&self, amount: u64) {
        IntCounter::inc_by(self, amount);
    }
}

impl<T: MetricsCounter> MetricsCounter for &T {
    fn inc_by(&self, amount: u64) {
        (**self).inc_by(amount)
    }
}

/// A counter for tests, or where the result is read directly.
#[derive(Default)]
pub struct DummyCounter(AtomicU64);

impl DummyCounter {
    pub fn new() -> Self {
        DummyCounter(AtomicU64::new(0))
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl MetricsCounter for DummyCounter {
    fn inc_by(&self, amount: u64) {
        self.0.fetch_add(amount, Ordering::Relaxed);
    }
}

/// Serves the metrics of `registry` at `http://{addr}/metrics` in the Prometheus text format
/// (HTTP/1.1 only), until the program ends.
///
/// Returns only if binding fails.
pub async fn serve_metrics(registry: Registry, addr: SocketAddr) -> Result<Infallible> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics server to {}", addr))?;
    info!("Serving metrics on http://{}/metrics", addr);
    serve_metrics_on(registry, listener).await
}

/// Serves the metrics endpoint on an already bound listener.
async fn serve_metrics_on(registry: Registry, listener: TcpListener) -> Result<Infallible> {
    loop {
        let (stream, peer) = accept_retrying(|| listener.accept()).await;

        let registry = registry.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let response = metrics_response(&registry, &request);
                async move { Ok::<_, Infallible>(response) }
            });
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

/// Returns the next connection that `accept` returns. On errors, e.g. when the process ran out of
/// file descriptors, logs them and tries again after a pause.
async fn accept_retrying<T, Fut>(mut accept: impl FnMut() -> Fut) -> T
where
    Fut: Future<Output = std::io::Result<T>>,
{
    loop {
        match accept().await {
            Ok(accepted) => return accepted,
            Err(e) => {
                warn!("Failed to accept metrics connection: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
            }
        }
    }
}

/// Builds the response to a request for the metrics server.
///
/// `/metrics` returns the metrics of `registry` in the Prometheus text format, every other path
/// is answered with 404.
fn metrics_response<B>(registry: &Registry, request: &Request<B>) -> Response<Full<Bytes>> {
    if request.uri().path() != "/metrics" {
        return plain_response(StatusCode::NOT_FOUND, "not found\n");
    }

    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&registry.gather(), &mut buffer) {
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

/// Returns the metrics of `registry` in one line, each summed over its labels, e.g.
/// `tunnels_total: 1 | tunnels_active: 1`, without the common `prefix` of their names.
pub fn summary(registry: &Registry, prefix: &str) -> String {
    registry
        .gather()
        .iter()
        .map(|family| {
            let total: f64 = family
                .get_metric()
                .iter()
                .map(|metric| match family.get_field_type() {
                    MetricType::GAUGE => metric.get_gauge().get_value(),
                    _ => metric.get_counter().get_value(),
                })
                .sum();
            let name = family.name();
            format!("{}: {}", name.strip_prefix(prefix).unwrap_or(name), total)
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Prints [`summary`] to stderr every second, if it changed.
pub async fn print_metrics_loop(registry: Registry, prefix: &str) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut previous = String::new();
    loop {
        tick.tick().await;
        let current = summary(&registry, prefix);
        if current != previous {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            eprintln!("{} | {}", timestamp, current);
            previous = current;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn registry() -> (Registry, IntCounter) {
        let registry = Registry::new();
        let requests = counter(&registry, "test_", "requests_total", "Requests");
        (registry, requests)
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let (registry, counter) = registry();
        counter.inc();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_metrics_on(registry, listener));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        assert!(
            response.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected response: {}",
            response
        );
        let content_type = format!("content-type: {}\r\n", TextEncoder::new().format_type());
        assert!(
            response.to_lowercase().contains(&content_type),
            "Missing Content-Type header: {}",
            response
        );
        // Only the registry's metrics.
        assert!(
            response.ends_with("# TYPE test_requests_total counter\ntest_requests_total 1\n"),
            "{}",
            response
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_accept_errors_are_retried_after_a_pause() {
        let start = tokio::time::Instant::now();
        let mut attempts = 0;
        let accepted = accept_retrying(|| {
            attempts += 1;
            let attempt = attempts;
            async move {
                match attempt {
                    1 | 2 => Err(std::io::Error::other("too many open files")),
                    _ => Ok(attempt),
                }
            }
        })
        .await;
        assert_eq!(accepted, 3);
        assert_eq!(start.elapsed(), ACCEPT_ERROR_DELAY * 2);
    }

    #[tokio::test]
    async fn test_invalid_requests_are_answered_with_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_metrics_on(Registry::new(), listener));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"not http\r\n\r\n").await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{}",
            response
        );
    }

    #[tokio::test]
    async fn test_binding_a_used_address_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let err = serve_metrics(Registry::new(), addr).await.unwrap_err();
        assert!(
            err.to_string().contains("failed to bind metrics server"),
            "{:#}",
            err
        );
    }

    #[test]
    fn test_unknown_path_is_not_found() {
        let request = Request::builder().uri("/other").body(()).unwrap();
        let response = metrics_response(&Registry::new(), &request);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_summary_sums_over_labels() {
        let (registry, counter) = registry();
        counter.inc_by(3);
        let by_client = counter_vec(&registry, "test_", "bytes_total", "Bytes", &["client"]);
        by_client.with_label_values(&["home"]).inc_by(5);
        by_client.with_label_values(&["office"]).inc_by(7);
        let active = gauge_vec(&registry, "test_", "active", "Active", &["client"]);
        active.with_label_values(&["home"]).set(2);

        assert_eq!(
            summary(&registry, "test_"),
            "active: 2 | bytes_total: 12 | requests_total: 3"
        );
    }

    #[test]
    fn test_active_counts_while_it_lives() {
        let registry = Registry::new();
        let running = gauge(&registry, "test_", "running", "Running");
        let first = Active::new(&running);
        let second = Active::new(&running);
        assert_eq!(running.get(), 2);
        drop(first);
        assert_eq!(running.get(), 1);
        drop(second);
        assert_eq!(running.get(), 0);
    }

    #[test]
    #[should_panic(expected = "duplicate metric name")]
    fn test_metric_names_are_unique() {
        let registry = Registry::new();
        counter(&registry, "test_", "requests_total", "Requests");
        counter(&registry, "test_", "requests_total", "Requests");
    }

    #[test]
    fn test_counters_count_through_references() {
        fn count(counter: impl MetricsCounter, amount: u64) {
            counter.inc_by(amount);
        }
        let counter = DummyCounter::new();
        count(&counter, 2);
        let (_registry, prometheus_counter) = registry();
        count(&prometheus_counter, 3);
        assert_eq!((counter.get(), prometheus_counter.get()), (2, 3));
    }
}
