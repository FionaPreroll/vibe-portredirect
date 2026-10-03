// PortRedirect - Graceful shutdown
//
// Both programs shut down in two steps. On the first SIGINT or SIGTERM, they drain: they start
// no new forwarded connections and tell the other side with DRAIN, while running forwarded
// connections may finish, for at most the shutdown timeout. Then, or on a second signal, they
// close the rest.
//
// License: GPL-3.0-only

use std::future::Future;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::info;

/// Default for --shutdown-timeout: short enough for container runtimes that kill a program 10
/// seconds after SIGTERM, long enough for typical requests.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// A request to shut down, in two steps: first to drain, then to stop.
///
/// Clones share the request. The running forwarded connections are tracked here, so draining can
/// wait for them.
#[derive(Clone, Debug)]
pub struct Shutdown {
    drain: CancellationToken,
    stop: CancellationToken,
    connections: TaskTracker,
    timeout: Duration,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new(DEFAULT_SHUTDOWN_TIMEOUT)
    }
}

impl Shutdown {
    /// Returns a shutdown that is not requested yet, and lets running connections finish for at
    /// most `timeout` when draining.
    pub fn new(timeout: Duration) -> Self {
        Self {
            drain: CancellationToken::new(),
            stop: CancellationToken::new(),
            connections: TaskTracker::new(),
            timeout,
        }
    }

    /// Returns a shutdown that the process's signals request: the first SIGINT or SIGTERM drains,
    /// the second one stops.
    pub fn on_signals(timeout: Duration) -> Self {
        let shutdown = Self::new(timeout);
        tokio::spawn(request_on_signals(shutdown.clone()));
        shutdown
    }

    /// How long running connections may take to finish when draining.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Starts draining: no new forwarded connections, running ones may finish.
    pub fn drain(&self) {
        self.drain.cancel();
    }

    /// Stops right away, closing running connections, also if draining didn't start yet.
    pub fn stop(&self) {
        self.drain.cancel();
        self.stop.cancel();
    }

    pub fn is_draining(&self) -> bool {
        self.drain.is_cancelled()
    }

    /// Completes when draining starts.
    pub async fn draining(&self) {
        self.drain.cancelled().await
    }

    /// Completes when stopping is requested.
    pub async fn stopping(&self) {
        self.stop.cancelled().await
    }

    /// Runs a forwarded connection, which draining waits for.
    pub fn spawn<F>(&self, connection: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.connections.spawn(connection)
    }

    /// Returns the number of running forwarded connections.
    pub fn running(&self) -> usize {
        self.connections.len()
    }

    /// Lets the running forwarded connections finish, see [`Shutdown::connections_finished`], and
    /// logs how it went.
    pub async fn finish_connections(&self) {
        info!(
            "Waiting up to {:?} for running forwarded connections to finish: {}",
            self.timeout,
            self.running()
        );
        if self.connections_finished().await {
            info!("All forwarded connections finished");
        } else {
            info!(
                "Closing forwarded connections that didn't finish: {}",
                self.running()
            );
        }
    }

    /// Waits until the running forwarded connections finished, for at most the timeout, or until
    /// stopping is requested. Returns whether they finished.
    pub async fn connections_finished(&self) -> bool {
        // Connections started from now on are waited for, too.
        self.connections.close();
        tokio::select! {
            biased;
            () = self.connections.wait() => true,
            () = self.stopping() => false,
            () = tokio::time::sleep(self.timeout) => false,
        }
    }
}

/// Requests `shutdown` to drain on the first SIGINT or SIGTERM, and to stop on the second.
async fn request_on_signals(shutdown: Shutdown) {
    let mut signals = Signals::new();
    let signal = signals.recv().await;
    info!(
        "Received {}, shutting down: running connections may finish within {:?}, another signal closes them right away",
        signal,
        shutdown.timeout()
    );
    shutdown.drain();
    let signal = signals.recv().await;
    info!("Received {}, closing running connections", signal);
    shutdown.stop();
}

/// Listens for SIGINT and SIGTERM.
struct Signals {
    #[cfg(unix)]
    interrupt: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    terminate: Option<tokio::signal::unix::Signal>,
}

impl Signals {
    /// Starts listening, so no signal gets lost between two calls of [`Signals::recv`].
    fn new() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let listen = |kind: SignalKind, name: &str| {
                signal(kind)
                    .inspect_err(|e| tracing::warn!("Failed to listen for {}: {}", name, e))
                    .ok()
            };
            Self {
                interrupt: listen(SignalKind::interrupt(), "SIGINT"),
                terminate: listen(SignalKind::terminate(), "SIGTERM"),
            }
        }
        #[cfg(not(unix))]
        Self {}
    }

    /// Waits for the next signal and returns its name.
    async fn recv(&mut self) -> &'static str {
        #[cfg(unix)]
        {
            async fn next(signal: &mut Option<tokio::signal::unix::Signal>) {
                match signal {
                    Some(signal) => {
                        signal.recv().await;
                    }
                    None => std::future::pending().await,
                }
            }
            tokio::select! {
                () = next(&mut self.interrupt) => "SIGINT",
                () = next(&mut self.terminate) => "SIGTERM",
            }
        }
        #[cfg(not(unix))]
        {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::warn!("Failed to listen for Ctrl-C: {}", e);
                std::future::pending::<()>().await;
            }
            "Ctrl-C"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::oneshot;
    use tokio::time::Instant;

    #[tokio::test(start_paused = true)]
    async fn test_draining_waits_for_running_connections() {
        let shutdown = Shutdown::new(Duration::from_secs(60));
        let (finish, finished) = oneshot::channel::<()>();
        let done = Arc::new(AtomicBool::new(false));
        let connection_done = Arc::clone(&done);
        shutdown.spawn(async move {
            let _ = finished.await;
            connection_done.store(true, Ordering::SeqCst);
        });
        assert_eq!(shutdown.running(), 1);
        assert!(!shutdown.is_draining());

        shutdown.drain();
        assert!(shutdown.is_draining());
        shutdown.draining().await;
        let start = Instant::now();
        let waiting = tokio::spawn({
            let shutdown = shutdown.clone();
            async move { shutdown.connections_finished().await }
        });
        tokio::time::sleep(Duration::from_secs(10)).await;
        // Connections that start while draining are waited for, too.
        let (finish_late, finished_late) = oneshot::channel::<()>();
        shutdown.spawn(async move {
            let _ = finished_late.await;
        });
        finish.send(()).unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(!waiting.is_finished());

        finish_late.send(()).unwrap();
        assert!(waiting.await.unwrap());
        assert!(done.load(Ordering::SeqCst));
        assert_eq!(start.elapsed(), Duration::from_secs(20));
        assert_eq!(shutdown.running(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_draining_ends_after_the_timeout() {
        let shutdown = Shutdown::new(Duration::from_secs(5));
        assert_eq!(shutdown.timeout(), Duration::from_secs(5));
        shutdown.spawn(std::future::pending::<()>());
        shutdown.drain();

        let start = Instant::now();
        assert!(!shutdown.connections_finished().await);
        assert_eq!(start.elapsed(), Duration::from_secs(5));
        assert_eq!(shutdown.running(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_stopping_ends_draining_right_away() {
        let shutdown = Shutdown::default();
        assert_eq!(shutdown.timeout(), DEFAULT_SHUTDOWN_TIMEOUT);
        shutdown.spawn(std::future::pending::<()>());
        // Stopping implies draining.
        shutdown.stop();
        assert!(shutdown.is_draining());
        shutdown.stopping().await;

        let start = Instant::now();
        assert!(!shutdown.connections_finished().await);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn test_draining_without_connections_ends_right_away() {
        let shutdown = Shutdown::new(Duration::ZERO);
        shutdown.drain();
        assert!(shutdown.connections_finished().await);
    }
}
