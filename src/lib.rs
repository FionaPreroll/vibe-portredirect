// PortRedirect
//
// License: GPL-3.0-only

//! PortRedirect forwards TCP connections through a QUIC connection, with two programs:
//! `portredirect_server` and `portredirect_client`. The
//! [README](https://github.com/FionaPreroll/vibe-portredirect#readme) explains how to use them.
//!
//! This library is not an API. It only holds the code of the two programs, and nothing in it is
//! meant for other crates: its only public items are the programs' entry points, which may change
//! in any release.

// Public items would fall under the compatibility promise of the crate's version. They need docs,
// so a module made public by accident fails the lint check.
#![warn(missing_docs)]
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use std::fmt::{self, Write as _};
use std::io::IsTerminal;
use std::{path::PathBuf, time::Duration};
use tracing::field::Field;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::field::MakeExt;
use tracing_subscriber::fmt::format::{debug_fn, Writer};
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::EnvFilter;

mod app_data;
mod bi_stream;
mod client;
mod config;
mod forward;
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod fuzz;
mod host_port;
mod limits;
mod metrics;
mod private_files;
mod protocol;
mod psk;
mod quic;
mod server;
mod shutdown;
#[cfg(test)]
mod tests;

#[doc(hidden)]
pub use client::main::main as client_main;
#[doc(hidden)]
pub use server::main::main as server_main;

/// Returns the path to the configuration directory, creating it if necessary.
pub(crate) fn get_config_dir(override_config_dir: Option<PathBuf>) -> Result<PathBuf> {
    // Use the override if provided, otherwise fall back to the platform's config directory.
    let config_dir = if let Some(override_path) = override_config_dir {
        override_path
    } else {
        let mut config_dir =
            dirs::config_dir().context("Failed to find your platform's config directory")?;
        config_dir.push("portredirect");
        config_dir
    };

    // Create the directory if it doesn't exist. It holds the private key, so keep it private.
    private_files::create_private_dir_all(&config_dir).context("create config dir")?;

    Ok(config_dir)
}

/// Sets up logging to stderr for messages up to `max_level`, with colors only on a terminal.
///
/// The `RUST_LOG` environment variable, if set, takes precedence and can set levels per module,
/// e.g. `RUST_LOG=info,portredirect::forward=debug`.
pub(crate) fn init_logging(max_level: LevelFilter) {
    let filter = match std::env::var("RUST_LOG") {
        Ok(directives) if !directives.trim().is_empty() => EnvFilter::try_new(&directives)
            .unwrap_or_else(|e| {
                // Logging isn't set up yet.
                eprintln!("Ignoring invalid RUST_LOG {:?}: {}", directives, e);
                EnvFilter::default().add_directive(max_level.into())
            }),
        _ => EnvFilter::default().add_directive(max_level.into()),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .fmt_fields(escaping_fields())
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(true)
        .with_line_number(true)
        .init();
}

/// Formats the fields of log messages, including the message itself, with control characters
/// escaped, see [`Escaped`].
///
/// Log messages may contain text from the peer, e.g. the reason it gave for closing the
/// connection, which is part of the error. Escaped, the peer can't start a new line with it, and
/// make it look like another log message.
fn escaping_fields() -> impl for<'writer> FormatFields<'writer> + 'static {
    debug_fn(
        |writer: &mut Writer<'_>, field: &Field, value: &dyn fmt::Debug| {
            if field.name() == "message" {
                write!(writer, "{}", Escaped(format_args!("{:?}", value)))
            } else {
                write!(writer, "{}={}", field, Escaped(format_args!("{:?}", value)))
            }
        },
    )
    .delimited(" ")
}

/// Displays its value with control characters escaped like in Rust strings, e.g. a line break
/// as `\n`, as well as Unicode line and paragraph separators.
struct Escaped<T>(T);

impl<T: fmt::Display> fmt::Display for Escaped<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Escaping<'a, 'b>(&'a mut fmt::Formatter<'b>);

        impl fmt::Write for Escaping<'_, '_> {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                for c in text.chars() {
                    if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
                        write!(self.0, "{}", c.escape_default())?;
                    } else {
                        self.0.write_char(c)?;
                    }
                }
                Ok(())
            }
        }

        write!(Escaping(f), "{}", self.0)
    }
}

pub(crate) struct PortRedirectProtocol;

impl PortRedirectProtocol {
    pub const CONNECTION_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
    pub const CONNECTION_KEEPALIVE_READ_TIMEOUT: Duration = Duration::from_secs(30);
    pub const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);
    pub const CONFIGURATION_TIMEOUT: Duration = Duration::from_secs(10);
    /// Interval of QUIC keep-alive packets, below QUIC's default idle timeout of 30 seconds.
    pub const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(25);
    /// Default maximum number of concurrently forwarded connections per tunnel.
    pub const DEFAULT_MAX_FORWARDED_CONNECTIONS: usize = 512;

    // The following values are based on measurements over links with delay and loss, see
    // docs/PERFORMANCE.md.

    /// How much the peer may send on a QUIC stream, i.e. a forwarded connection, before the
    /// receiver reads it. A forwarded connection moves at most this much per round-trip time:
    /// about 1 Gbit/s at 50 ms and 400 Mbit/s at 150 ms.
    pub const QUIC_STREAM_RECEIVE_WINDOW: u32 = 8 << 20;
    /// How much the peer may send on all streams of a QUIC connection together before the
    /// receiver reads it. This bounds the memory a tunnel's receive buffers take.
    pub const QUIC_CONNECTION_RECEIVE_WINDOW: u32 = 32 << 20;
    /// How much a side may send on a QUIC connection before the peer acknowledges it.
    pub const QUIC_SEND_WINDOW: u64 = 32 << 20;
    /// The server's receive window for a connection until the client has authenticated: enough
    /// for the authentication, while an unauthenticated client can't make the server keep more.
    /// The server raises it to [`Self::QUIC_CONNECTION_RECEIVE_WINDOW`] afterwards.
    pub const QUIC_UNAUTHENTICATED_RECEIVE_WINDOW: u32 = 64 << 10;
    /// Size of the buffers of the UDP sockets. Datagrams often arrive in bursts, and a full
    /// buffer drops them, which QUIC takes for congestion, and slows down. Operating systems may
    /// limit it, Linux to `net.core.rmem_max` and `net.core.wmem_max`.
    pub const UDP_SOCKET_BUFFER_SIZE: usize = 4 << 20;
    /// Size of the buffer for each direction of a forwarded connection, for copying between the
    /// TCP connection and the QUIC stream. Larger buffers hardly make forwarding faster.
    pub const COPY_BUFFER_SIZE: usize = 64 << 10;
    /// How much of the TLS handshake QUIC buffers, e.g. data that arrives out of order. Far
    /// more than the server's certificate takes.
    pub const QUIC_CRYPTO_BUFFER_SIZE: usize = 64 << 10;
}
