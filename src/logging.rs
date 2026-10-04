// PortRedirect - Logging setup, shared by both programs
//
// License: GPL-3.0-only

use clap::ValueEnum;
use serde::Deserialize;
use std::fmt::{self, Write as _};
use std::io::IsTerminal;
use std::sync::OnceLock;
use tracing::field::Field;
use tracing::level_filters::LevelFilter;
use tracing::Subscriber;
use tracing_subscriber::field::MakeExt;
use tracing_subscriber::filter::Directive;
use tracing_subscriber::fmt::format::{debug_fn, Writer};
use tracing_subscriber::fmt::{FormatFields, MakeWriter};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Target of the client's log of forwarded connections, which `--log-connections` switches on
/// independently of the log level.
pub const CONNECTION_LOG: &str = "portredirect::connections";

/// The format of log messages.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Text, one message per line.
    #[default]
    Text,
    /// One JSON object per line, e.g. for log collectors.
    Json,
}

/// Replaces the filter of a subscriber, see [`subscriber`].
type FilterReload = Box<dyn Fn(EnvFilter) -> Result<(), String> + Send + Sync>;

/// Replaces the filter of the subscriber that [`init_logging`] set up.
static FILTER_RELOAD: OnceLock<FilterReload> = OnceLock::new();

/// Sets up logging to stderr for messages up to `max_level`, in `format`, with colors only on a
/// terminal. With `log_connections`, the client logs each forwarded connection, see
/// [`CONNECTION_LOG`].
///
/// The `RUST_LOG` environment variable, if set, takes precedence and can set levels per module,
/// e.g. `RUST_LOG=info,portredirect::forward=debug`.
pub(crate) fn init_logging(max_level: LevelFilter, format: LogFormat, log_connections: bool) {
    let rust_log = std::env::var("RUST_LOG").ok();
    let filter = filter(max_level, log_connections, rust_log.as_deref());
    let ansi = std::io::stderr().is_terminal();
    let (subscriber, reload) = subscriber(filter, format, std::io::stderr, ansi);
    let _ = FILTER_RELOAD.set(reload);
    subscriber.init();
}

/// Logs messages up to `max_level` from now on, and the connection log if `log_connections`,
/// see [`init_logging`]. Fails if `RUST_LOG` sets the levels, as it takes precedence, or logging
/// isn't set up.
pub(crate) fn set_log_level(max_level: LevelFilter, log_connections: bool) -> Result<(), String> {
    let rust_log = std::env::var("RUST_LOG").ok();
    set_filter(
        FILTER_RELOAD.get(),
        max_level,
        log_connections,
        rust_log.as_deref(),
    )
}

/// Replaces the filter with `reload` by the one for `max_level` and `log_connections`, unless
/// the valid directives of `rust_log` take precedence, see [`filter`].
fn set_filter(
    reload: Option<&FilterReload>,
    max_level: LevelFilter,
    log_connections: bool,
    rust_log: Option<&str>,
) -> Result<(), String> {
    let directives = rust_log.filter(|directives| !directives.trim().is_empty());
    if directives.is_some_and(|directives| EnvFilter::try_new(directives).is_ok()) {
        return Err("RUST_LOG sets the levels, it takes precedence".into());
    }
    let reload = reload.ok_or("logging isn't set up")?;
    reload(filter(max_level, log_connections, None))
}

/// Returns the filter for messages up to `max_level`, and the connection log if
/// `log_connections`, unless `rust_log` has directives, which take precedence.
fn filter(max_level: LevelFilter, log_connections: bool, rust_log: Option<&str>) -> EnvFilter {
    let connections: Directive = format!(
        "{}={}",
        CONNECTION_LOG,
        if log_connections { "info" } else { "off" }
    )
    .parse()
    .expect("the connection log's directive is valid");
    let Some(directives) = rust_log.filter(|directives| !directives.trim().is_empty()) else {
        return EnvFilter::default()
            .add_directive(max_level.into())
            .add_directive(connections);
    };
    match EnvFilter::try_new(directives) {
        // RUST_LOG may switch the connection log on or off itself.
        Ok(filter) if directives.contains(CONNECTION_LOG) => filter,
        Ok(filter) => filter.add_directive(connections),
        Err(e) => {
            // Logging isn't set up yet.
            eprintln!("Ignoring invalid RUST_LOG {:?}: {}", directives, e);
            EnvFilter::default()
                .add_directive(max_level.into())
                .add_directive(connections)
        }
    }
}

/// Returns the subscriber that writes the messages `filter` lets through to `writer`, in
/// `format`, with colors if `ansi`, and how to replace its filter later.
fn subscriber<W>(
    filter: EnvFilter,
    format: LogFormat,
    writer: W,
    ansi: bool,
) -> (Box<dyn Subscriber + Send + Sync>, FilterReload)
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_target(true)
        .with_line_number(true);
    match format {
        LogFormat::Text => {
            let builder = builder
                .fmt_fields(escaping_fields())
                .with_ansi(ansi)
                .with_filter_reloading();
            let handle = builder.reload_handle();
            let reload = move |filter| handle.reload(filter).map_err(|e| e.to_string());
            (Box::new(builder.finish()), Box::new(reload))
        }
        // JSON escapes control characters in strings itself.
        LogFormat::Json => {
            let builder = builder
                .json()
                .flatten_event(true)
                .with_ansi(false)
                .with_filter_reloading();
            let handle = builder.reload_handle();
            let reload = move |filter| handle.reload(filter).map_err(|e| e.to_string());
            (Box::new(builder.finish()), Box::new(reload))
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// Collects what is logged.
    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);

    impl Output {
        fn lines(&self) -> Vec<String> {
            let output = self.0.lock().unwrap();
            String::from_utf8_lossy(&output)
                .lines()
                .map(String::from)
                .collect()
        }
    }

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

    /// Returns what `log` logs with the filter of `max_level` and `log_connections`, in
    /// `format`.
    fn logged(
        max_level: LevelFilter,
        log_connections: bool,
        rust_log: Option<&str>,
        format: LogFormat,
        log: impl FnOnce(),
    ) -> Vec<String> {
        let output = Output::default();
        let filter = filter(max_level, log_connections, rust_log);
        let (subscriber, _) = subscriber(filter, format, output.clone(), false);
        tracing::subscriber::with_default(subscriber, log);
        output.lines()
    }

    #[test]
    fn test_log_level_can_change() {
        for format in [LogFormat::Text, LogFormat::Json] {
            let output = Output::default();
            let filter = filter(LevelFilter::INFO, false, None);
            let (subscriber, reload) = subscriber(filter, format, output.clone(), false);
            tracing::subscriber::with_default(subscriber, || {
                tracing::debug!("not logged");
                set_filter(Some(&reload), LevelFilter::DEBUG, false, None).unwrap();
                tracing::debug!("logged");
                tracing::info!(target: CONNECTION_LOG, "Connection opened");
                set_filter(Some(&reload), LevelFilter::WARN, true, Some("")).unwrap();
                tracing::info!("not logged");
                tracing::info!(target: CONNECTION_LOG, "Connection closed");
            });
            let lines = output.lines();
            assert_eq!(lines.len(), 2, "{:?}", lines);
            assert!(lines[0].contains("logged") && !lines[0].contains("not logged"));
            assert!(lines[1].contains("Connection closed"), "{}", lines[1]);
        }

        // RUST_LOG takes precedence, unless it is invalid, see filter().
        let (_subscriber, reload) = subscriber(
            EnvFilter::default(),
            LogFormat::Text,
            Output::default(),
            false,
        );
        let reload = Some(&reload);
        let err = set_filter(reload, LevelFilter::DEBUG, false, Some("info")).unwrap_err();
        assert!(err.contains("RUST_LOG"), "{}", err);
        assert!(set_filter(reload, LevelFilter::DEBUG, false, Some("portredirect=loud")).is_ok());
        let err = set_filter(None, LevelFilter::DEBUG, false, None).unwrap_err();
        assert_eq!(err, "logging isn't set up");
    }

    /// A reason a peer gave for closing the connection, which is part of errors, with a line
    /// break and an escape sequence that clears the terminal.
    const REASON: &str = "bye\n2026-10-04T06:00:00Z  INFO fake message\u{1b}[2J";

    #[test]
    fn test_log_messages_escape_control_characters() {
        let lines = logged(LevelFilter::INFO, false, None, LogFormat::Text, || {
            tracing::warn!(peer = %REASON, "Connection dropped: closed by peer: {}", REASON);
        });

        assert_eq!(lines.len(), 1, "{:?}", lines);
        let escaped = r"bye\n2026-10-04T06:00:00Z  INFO fake message\u{1b}[2J";
        assert!(
            lines[0].contains(&format!("closed by peer: {} peer={}", escaped, escaped)),
            "{}",
            lines[0]
        );
        let separators = format!("{}", Escaped("\t\r\u{85}\u{2028}\u{2029} ok"));
        assert_eq!(separators, r"\t\r\u{85}\u{2028}\u{2029} ok");
    }

    #[test]
    fn test_json_format_has_one_object_per_message() {
        let lines = logged(LevelFilter::INFO, false, None, LogFormat::Json, || {
            let span = tracing::info_span!("tunnel", client = "web");
            let _entered = span.enter();
            tracing::warn!(peer = %REASON, "Connection dropped: closed by peer: {}", REASON);
            tracing::debug!("not logged");
        });

        assert_eq!(lines.len(), 1, "{:?}", lines);
        let message: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(message["level"], "WARN");
        assert_eq!(
            message["message"],
            format!("Connection dropped: closed by peer: {}", REASON)
        );
        assert_eq!(message["peer"], REASON);
        assert_eq!(message["target"], module_path!());
        assert_eq!(message["span"]["name"], "tunnel");
        assert_eq!(message["span"]["client"], "web");
        assert!(message["timestamp"].is_string(), "{}", lines[0]);
    }

    #[test]
    fn test_connection_log_is_independent_of_the_log_level() {
        let log = || {
            tracing::info!(target: CONNECTION_LOG, "Connection opened");
            tracing::info!("Other message");
        };
        for (max_level, log_connections, rust_log, expected) in [
            (LevelFilter::INFO, false, None, &["Other message"][..]),
            (
                LevelFilter::INFO,
                true,
                None,
                &["Connection opened", "Other message"],
            ),
            (LevelFilter::WARN, true, None, &["Connection opened"]),
            (LevelFilter::OFF, false, None, &[]),
            // RUST_LOG takes precedence over --log-level, but not over --log-connections, ...
            (LevelFilter::OFF, false, Some("info"), &["Other message"]),
            (LevelFilter::OFF, true, Some("warn"), &["Connection opened"]),
            // ... unless it names the connection log itself.
            (
                LevelFilter::OFF,
                false,
                Some("warn,portredirect::connections=info"),
                &["Connection opened"],
            ),
            // An invalid RUST_LOG is ignored.
            (
                LevelFilter::INFO,
                false,
                Some("portredirect=loud"),
                &["Other message"],
            ),
        ] {
            let lines = logged(max_level, log_connections, rust_log, LogFormat::Text, log);
            assert_eq!(
                lines.len(),
                expected.len(),
                "{:?} {} {:?}: {:?}",
                max_level,
                log_connections,
                rust_log,
                lines
            );
            for (line, message) in lines.iter().zip(expected) {
                assert!(line.ends_with(message), "{}", line);
            }
        }
    }
}
