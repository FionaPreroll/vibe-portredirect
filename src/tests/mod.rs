// PortRedirect - In-process end-to-end tests
//
// Server and client run in the test process and talk over localhost. These tests use the crate's
// internals, so they live in the crate; tests/ holds the tests of the programs themselves.
//
// License: GPL-3.0-only

mod quic_end_to_end_minimal;
mod quic_end_to_end_multiple_clients;
mod tunnel_end_to_end;

use tracing::subscriber::DefaultGuard;

/// Sends the log messages of the current thread to the test's output, which is shown if the test
/// fails, until the returned guard is dropped.
///
/// Each test runs on a thread of its own, and a `#[tokio::test]` runs its tasks on that thread,
/// too. A global subscriber would also log the unit tests that happen to run meanwhile.
fn capture_logs() -> DefaultGuard {
    tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .finish(),
    )
}
