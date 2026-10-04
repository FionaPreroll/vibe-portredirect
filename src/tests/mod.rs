// PortRedirect - In-process end-to-end tests
//
// Server and client run in the test process and talk over localhost. These tests use the crate's
// internals, so they live in the crate; tests/ holds the tests of the programs themselves.
//
// License: GPL-3.0-only

mod quic_end_to_end_minimal;
mod quic_end_to_end_multiple_clients;
mod tunnel_end_to_end;

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::fmt::MakeWriter;

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

/// Ports for the tests' servers and listeners, handed out one at a time.
///
/// The operating system picks the ports of sockets bound to port 0, which includes outgoing
/// connections, from a range above these: from 32768 on Linux, from 49152 on macOS and Windows.
/// So neither another test nor such a socket can take a port between a test finding it free and
/// binding it. `tests/cli.rs` uses the ports below these.
const TEST_PORTS: Range<u16> = 20000..32000;

/// Returns a port from [`TEST_PORTS`] that no other test got, and that `is_free` finds free.
fn unused_port(is_free: impl Fn(SocketAddr) -> bool) -> u16 {
    // A random start makes collisions with test programs running at the same time unlikely.
    static START: LazyLock<usize> =
        LazyLock::new(|| RandomState::new().hash_one(0) as usize % TEST_PORTS.len());
    static HANDED_OUT: AtomicUsize = AtomicUsize::new(0);
    let len = TEST_PORTS.len();
    (0..len)
        .map(|_| HANDED_OUT.fetch_add(1, Ordering::Relaxed))
        .map(|n| TEST_PORTS.start + ((*START + n) % len) as u16)
        .find(|&port| is_free(SocketAddr::from((Ipv4Addr::LOCALHOST, port))))
        .expect("no free port for tests")
}

/// Returns a TCP port on localhost for a test alone, see [`TEST_PORTS`].
fn free_tcp_port() -> u16 {
    unused_port(|addr| std::net::TcpListener::bind(addr).is_ok())
}

/// Returns a UDP port on localhost for a test alone, see [`TEST_PORTS`].
fn free_udp_port() -> u16 {
    unused_port(|addr| std::net::UdpSocket::bind(addr).is_ok())
}

#[test]
fn test_log_messages_escape_control_characters() {
    /// Collects what is logged.
    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Output {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Output {
        type Writer = Output;

        fn make_writer(&'a self) -> Output {
            self.clone()
        }
    }

    let output = Output::default();
    let subscriber = tracing_subscriber::fmt()
        .fmt_fields(crate::escaping_fields())
        .with_writer(output.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        // E.g. the reason a peer gave for closing the connection, which is part of the error.
        let reason = "bye\n2026-10-04T06:00:00Z  INFO fake message\u{1b}[2J";
        tracing::warn!(peer = %reason, "Connection dropped: closed by peer: {}", reason);
    });

    let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert_eq!(output.lines().count(), 1, "{}", output);
    let escaped = r"bye\n2026-10-04T06:00:00Z  INFO fake message\u{1b}[2J";
    assert!(
        output.contains(&format!("closed by peer: {} peer={}", escaped, escaped)),
        "{}",
        output
    );
    let separators = format!("{}", crate::Escaped("\t\r\u{85}\u{2028}\u{2029} ok"));
    assert_eq!(separators, r"\t\r\u{85}\u{2028}\u{2029} ok");
}
