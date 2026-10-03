// PortRedirect Client - Configuration from the command line, the environment and the
// configuration file, see crate::config
//
// License: GPL-3.0-only

use anyhow::{anyhow, Result};
use clap::error::ErrorKind;
use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser};
use serde::Deserialize;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32};
use std::path::{Path, PathBuf};
use tracing::level_filters::LevelFilter;

use crate::config::{self, merge, merge_option, read_config_file, required, resolve_path};
use crate::protocol::auth::ClientName;
use crate::psk::{PskArgs, PskSource, PSK_ENV_VAR};
use crate::PortRedirectProtocol;

/// PortRedirect client: asks the server to listen on a port and forwards the connections the
/// server accepts there to the destination.
///
/// The client reconnects whenever the connection to the server ends. It exits with code 0 on
/// SIGINT or SIGTERM, and with code 1 if it can't work as configured, e.g. because the server
/// rejects its PSK or port.
#[derive(Parser, Debug)]
#[command(name = "portredirect_client", version)]
pub struct Args {
    /// TOML file with settings. Its keys are the names of the options without the leading
    /// dashes, e.g. max-connections = 100. Options given on the command line or in the
    /// environment take precedence.
    #[clap(long, value_name = "PATH")]
    pub config_file: Option<PathBuf>,

    /// Full path to configuration directory, with the server's certificate cert.der.
    #[clap(long, value_name = "PATH")]
    pub config_dir: Option<PathBuf>,

    /// Destination host for data coming from QUIC connections. Required, here or in the
    /// configuration file.
    #[clap(long, required_unless_present = "config_file")]
    pub destination_host: Option<String>,

    /// Destination port (currently TCP only). Required, here or in the configuration file.
    #[clap(
        long,
        value_parser = clap::value_parser!(u16).range(1..),
        required_unless_present = "config_file"
    )]
    pub destination_port: Option<u16>,

    /// TCP port the server should listen on for external connections.
    /// Must be allowed by the server's --allowed-client-ports. Required, here or in the
    /// configuration file.
    #[clap(
        long,
        value_parser = clap::value_parser!(u16).range(1..),
        required_unless_present = "config_file"
    )]
    pub remote_listen_port: Option<u16>,

    /// Name to authenticate with, if the server knows several clients: 1 to 64 letters, digits,
    /// dots, underscores or hyphens.
    #[clap(long, default_value = ClientName::DEFAULT)]
    pub client_name: ClientName,

    /// QUIC connection remote host (server). Required, here or in the configuration file.
    #[clap(long, required_unless_present = "config_file")]
    pub quic_remote_host: Option<String>,

    /// QUIC connection remote port (server). Required, here or in the configuration file.
    #[clap(
        long,
        value_parser = clap::value_parser!(u16).range(1..),
        required_unless_present = "config_file"
    )]
    pub quic_remote_port: Option<u16>,

    /// QUIC connection local host to bind to (client).
    #[clap(long, default_value = "0.0.0.0")]
    pub quic_local_host: String,

    /// QUIC connection local port to bind to (client).
    #[clap(long, default_value = "0")]
    pub quic_local_port: u16,

    /// Serve Prometheus metrics via HTTP at /metrics, see --metrics-listen.
    #[clap(long)]
    pub provide_metrics: bool,

    /// Address and port for --provide-metrics. The endpoint has no authentication, only make it
    /// reachable from trusted networks.
    #[clap(long, default_value = "127.0.0.1:9898")]
    pub metrics_listen: SocketAddr,

    /// Maximum number of concurrently forwarded connections, i.e. connections to the destination.
    #[clap(
        long,
        default_value_t = PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS as u32,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub max_connections: u32,

    /// Name the server's TLS certificate must be issued for (Subject Alt Name), if it differs
    /// from --quic-remote-host. Must match the server's --quic-cert-hostname.
    #[clap(long)]
    pub quic_remote_hostname_match: Option<String>,

    #[command(flatten)]
    pub psk: PskArgs,

    /// Log messages up to this level: off, error, warn, info, debug or trace. The RUST_LOG
    /// environment variable, if set, takes precedence and can set levels per module.
    #[clap(long, default_value = "info")]
    pub log_level: LevelFilter,
}

/// The client's configuration file. Its keys are the names of the options.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ConfigFile {
    pub config_dir: Option<PathBuf>,
    pub destination_host: Option<String>,
    pub destination_port: Option<NonZeroU16>,
    pub remote_listen_port: Option<NonZeroU16>,
    #[serde(default, deserialize_with = "config::optional_parsed")]
    pub client_name: Option<ClientName>,
    pub quic_remote_host: Option<String>,
    pub quic_remote_port: Option<NonZeroU16>,
    pub quic_local_host: Option<String>,
    pub quic_local_port: Option<u16>,
    pub provide_metrics: Option<bool>,
    pub metrics_listen: Option<SocketAddr>,
    pub max_connections: Option<NonZeroU32>,
    pub quic_remote_hostname_match: Option<String>,
    pub quic_psk_file: Option<PathBuf>,
    #[serde(default, deserialize_with = "config::optional_parsed")]
    pub log_level: Option<LevelFilter>,
}

impl ConfigFile {
    /// Reads the configuration file at `path`. Relative paths in it are relative to its
    /// directory.
    pub fn read(path: &Path) -> Result<Self> {
        let mut file: Self = read_config_file(path)?;
        for relative in file
            .config_dir
            .iter_mut()
            .chain(file.quic_psk_file.iter_mut())
        {
            *relative = resolve_path(path, relative);
        }
        Ok(file)
    }
}

/// The client's configuration, from the command line, the environment and the configuration
/// file, in this order of precedence.
#[derive(Debug)]
pub struct Config {
    pub config_file: Option<PathBuf>,
    pub config_dir: Option<PathBuf>,
    pub destination_host: String,
    pub destination_port: u16,
    pub remote_listen_port: u16,
    pub client_name: ClientName,
    pub quic_remote_host: String,
    pub quic_remote_port: u16,
    pub quic_local_host: String,
    pub quic_local_port: u16,
    /// Address to serve Prometheus metrics on, if any.
    pub metrics_addr: Option<SocketAddr>,
    pub max_connections: usize,
    pub quic_remote_hostname_match: Option<String>,
    pub psk: PskSource,
    pub log_level: LevelFilter,
}

impl Config {
    /// Returns the configuration given by the program's command line, the environment and the
    /// configuration file. Exits with code 2 if it is invalid, like for invalid arguments.
    pub fn from_command_line() -> Self {
        let matches = Args::command().get_matches();
        Self::from_matches(&matches).unwrap_or_else(|e| {
            Args::command()
                .error(ErrorKind::InvalidValue, format!("{:#}", e).trim_end())
                .exit()
        })
    }

    /// Returns the configuration given by the command-line `matches`, the environment and the
    /// configuration file.
    pub fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let args = Args::from_arg_matches(matches)?;
        let file = match &args.config_file {
            Some(path) => ConfigFile::read(path)?,
            None => ConfigFile::default(),
        };

        let psk = args
            .psk
            .source(matches)
            .or(file.quic_psk_file.map(PskSource::File))
            .ok_or_else(|| {
                anyhow!(
                    "a pre-shared key is required: use --quic-psk-file, {}, --quic-psk, or quic-psk-file in the configuration file",
                    PSK_ENV_VAR
                )
            })?;
        let destination_host = merge_option(
            matches,
            "destination_host",
            args.destination_host,
            file.destination_host,
        );
        let destination_port = merge_option(
            matches,
            "destination_port",
            args.destination_port,
            file.destination_port.map(NonZeroU16::get),
        );
        let remote_listen_port = merge_option(
            matches,
            "remote_listen_port",
            args.remote_listen_port,
            file.remote_listen_port.map(NonZeroU16::get),
        );
        let quic_remote_host = merge_option(
            matches,
            "quic_remote_host",
            args.quic_remote_host,
            file.quic_remote_host,
        );
        let quic_remote_port = merge_option(
            matches,
            "quic_remote_port",
            args.quic_remote_port,
            file.quic_remote_port.map(NonZeroU16::get),
        );
        let provide_metrics = merge(
            matches,
            "provide_metrics",
            args.provide_metrics,
            file.provide_metrics,
        );
        let metrics_listen = merge(
            matches,
            "metrics_listen",
            args.metrics_listen,
            file.metrics_listen,
        );
        let max_connections = merge(
            matches,
            "max_connections",
            args.max_connections,
            file.max_connections.map(NonZeroU32::get),
        );
        Ok(Config {
            config_dir: merge_option(matches, "config_dir", args.config_dir, file.config_dir),
            destination_host: required(destination_host, "destination-host")?,
            destination_port: required(destination_port, "destination-port")?,
            remote_listen_port: required(remote_listen_port, "remote-listen-port")?,
            client_name: merge(matches, "client_name", args.client_name, file.client_name),
            quic_remote_host: required(quic_remote_host, "quic-remote-host")?,
            quic_remote_port: required(quic_remote_port, "quic-remote-port")?,
            quic_local_host: merge(
                matches,
                "quic_local_host",
                args.quic_local_host,
                file.quic_local_host,
            ),
            quic_local_port: merge(
                matches,
                "quic_local_port",
                args.quic_local_port,
                file.quic_local_port,
            ),
            metrics_addr: provide_metrics.then_some(metrics_listen),
            max_connections: max_connections as usize,
            quic_remote_hostname_match: merge_option(
                matches,
                "quic_remote_hostname_match",
                args.quic_remote_hostname_match,
                file.quic_remote_hostname_match,
            ),
            psk,
            log_level: merge(matches, "log_level", args.log_level, file.log_level),
            config_file: args.config_file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::fs;

    /// Returns the configuration given by the command-line `args`.
    fn config(args: &[&str]) -> Result<Config> {
        let matches =
            Args::command().try_get_matches_from(["portredirect_client"].iter().chain(args))?;
        Config::from_matches(&matches)
    }

    /// Returns the configuration given by the command-line `args` and a configuration file with
    /// `text`, which is in `dir` as `client.toml`.
    fn config_with_file(dir: &Path, text: &str, args: &[&str]) -> Result<Config> {
        let path = dir.join("client.toml");
        fs::write(&path, text)?;
        let mut args = args.to_vec();
        args.extend(["--config-file", path.to_str().unwrap()]);
        config(&args)
    }

    fn error_with_file(text: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let err = config_with_file(dir.path(), text, &[]).unwrap_err();
        format!("{:#}", err)
    }

    const FILE: &str = r#"
        config-dir = "state"
        destination-host = "backend"
        destination-port = 8080
        remote-listen-port = 443
        client-name = "home"
        quic-remote-host = "tunnel.example.com"
        quic-remote-port = 4434
        quic-local-host = "::"
        quic-local-port = 5000
        provide-metrics = true
        metrics-listen = "127.0.0.1:9999"
        max-connections = 20
        quic-remote-hostname-match = "tunnel"
        quic-psk-file = "psk"
        log-level = "debug"
    "#;

    const REQUIRED_ARGS: [&str; 12] = [
        "--destination-host",
        "localhost",
        "--destination-port",
        "80",
        "--remote-listen-port",
        "8443",
        "--quic-remote-host",
        "127.0.0.1",
        "--quic-remote-port",
        "4433",
        "--quic-psk-file",
        "/etc/portredirect/psk",
    ];

    #[test]
    fn test_command_line_with_defaults() -> Result<()> {
        let config = config(&REQUIRED_ARGS)?;
        assert!(config.config_file.is_none() && config.config_dir.is_none());
        assert_eq!(config.destination_host, "localhost");
        assert_eq!(config.destination_port, 80);
        assert_eq!(config.remote_listen_port, 8443);
        assert_eq!(config.client_name, ClientName::default());
        assert_eq!(config.quic_remote_host, "127.0.0.1");
        assert_eq!(config.quic_remote_port, 4433);
        assert_eq!(config.quic_local_host, "0.0.0.0");
        assert_eq!(config.quic_local_port, 0);
        assert_eq!(config.metrics_addr, None);
        assert_eq!(
            config.max_connections,
            PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS
        );
        assert_eq!(config.quic_remote_hostname_match, None);
        assert!(
            matches!(&config.psk, PskSource::File(path) if path == Path::new("/etc/portredirect/psk"))
        );
        assert_eq!(config.log_level, LevelFilter::INFO);
        Ok(())
    }

    #[test]
    fn test_configuration_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = config_with_file(dir.path(), FILE, &[])?;

        assert_eq!(config.config_file, Some(dir.path().join("client.toml")));
        // Relative to the file's directory.
        assert_eq!(config.config_dir, Some(dir.path().join("state")));
        assert_eq!(config.destination_host, "backend");
        assert_eq!(config.destination_port, 8080);
        assert_eq!(config.remote_listen_port, 443);
        assert_eq!(config.client_name.as_str(), "home");
        assert_eq!(config.quic_remote_host, "tunnel.example.com");
        assert_eq!(config.quic_remote_port, 4434);
        assert_eq!(config.quic_local_host, "::");
        assert_eq!(config.quic_local_port, 5000);
        assert_eq!(config.metrics_addr, Some("127.0.0.1:9999".parse()?));
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.quic_remote_hostname_match.as_deref(), Some("tunnel"));
        assert!(matches!(&config.psk, PskSource::File(path) if path == &dir.path().join("psk")));
        assert_eq!(config.log_level, LevelFilter::DEBUG);
        Ok(())
    }

    #[test]
    fn test_command_line_overrides_configuration_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = config_with_file(
            dir.path(),
            FILE,
            &[
                "--config-dir",
                "/var/lib/portredirect",
                "--destination-host",
                "localhost",
                "--destination-port",
                "80",
                "--remote-listen-port",
                "8443",
                "--client-name",
                "office",
                "--quic-remote-host",
                "127.0.0.1",
                "--quic-remote-port",
                "4433",
                "--quic-local-host",
                "0.0.0.0",
                "--quic-local-port",
                "0",
                "--metrics-listen",
                "127.0.0.1:9898",
                "--max-connections",
                "30",
                "--quic-remote-hostname-match",
                "localhost",
                "--quic-psk",
                "secret",
                "--log-level",
                "warn",
            ],
        )?;

        assert_eq!(config.config_dir, Some("/var/lib/portredirect".into()));
        assert_eq!(config.destination_host, "localhost");
        assert_eq!(config.destination_port, 80);
        assert_eq!(config.remote_listen_port, 8443);
        assert_eq!(config.client_name.as_str(), "office");
        assert_eq!(config.quic_remote_host, "127.0.0.1");
        assert_eq!(config.quic_remote_port, 4433);
        // Override the file, though they are the defaults.
        assert_eq!(config.quic_local_host, "0.0.0.0");
        assert_eq!(config.quic_local_port, 0);
        assert_eq!(config.metrics_addr, Some("127.0.0.1:9898".parse()?));
        assert_eq!(config.max_connections, 30);
        assert_eq!(
            config.quic_remote_hostname_match.as_deref(),
            Some("localhost")
        );
        assert!(matches!(config.psk, PskSource::CommandLine(_)));
        assert_eq!(config.psk.load()?.expose_secret(), "secret");
        assert_eq!(config.log_level, LevelFilter::WARN);

        // A flag can only switch a setting on.
        let mut args = REQUIRED_ARGS.to_vec();
        args.push("--provide-metrics");
        let config = config_with_file(dir.path(), "provide-metrics = false", &args)?;
        assert!(config.metrics_addr.is_some());
        Ok(())
    }

    #[test]
    fn test_required_settings() {
        let required = [
            ("destination-host", "\"localhost\""),
            ("destination-port", "80"),
            ("remote-listen-port", "443"),
            ("quic-remote-host", "\"127.0.0.1\""),
            ("quic-remote-port", "4433"),
            ("quic-psk-file", "\"psk\""),
        ];
        for (missing, _) in required {
            let text: String = required
                .iter()
                .filter(|(key, _)| *key != missing)
                .map(|(key, value)| format!("{} = {}\n", key, value))
                .collect();
            let message = error_with_file(&text);
            let expected = if missing == "quic-psk-file" {
                "a pre-shared key is required: use --quic-psk-file, PORTREDIRECT_QUIC_PSK, --quic-psk, or quic-psk-file in the configuration file".to_string()
            } else {
                format!(
                    "--{0} is required, on the command line or as {0} in the configuration file",
                    missing
                )
            };
            assert!(message.contains(&expected), "{}: {}", missing, message);
        }
        // Without configuration file, clap requires them.
        let err = config(&["--quic-psk", "secret"]).unwrap_err();
        let err = err.downcast::<clap::Error>().unwrap();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn test_invalid_values_are_rejected() {
        for (text, expected) in [
            ("destination-port = 0", "nonzero"),
            ("remote-listen-port = 65536", "invalid value"),
            (
                "client-name = \"my home\"",
                "invalid client name \"my home\"",
            ),
            ("metrics-listen = \"localhost\"", "invalid socket address"),
            ("quic-psk = \"secret\"", "unknown field `quic-psk`"),
            ("provide-metrics = \"yes\"", "invalid type"),
        ] {
            let message = error_with_file(text);
            assert!(message.contains(expected), "{:?}: {}", text, message);
        }
    }
}
