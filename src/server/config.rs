// PortRedirect Server - Configuration from the command line, the environment and the
// configuration file, see crate::config
//
// License: GPL-3.0-only

use anyhow::{anyhow, bail, Result};
use clap::builder::BoolishValueParser;
use clap::error::ErrorKind;
use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::level_filters::LevelFilter;

use crate::config::{
    self, check_renamed_environment, check_renamed_options, merge, merge_option, read_config_file,
    required, resolve_path,
};
use crate::logging::LogFormat;
use crate::protocol::auth::{ClientName, MAX_PSKS_PER_CLIENT};
use crate::psk::{PskArgs, PskSource, PSK_ENV_VAR};
use crate::quic::CongestionControl;
use crate::server::clients::{ClientEntry, ClientList};
use crate::server::{ForwardingLimits, PortSpec};
use crate::shutdown::DEFAULT_SHUTDOWN_TIMEOUT;
use crate::PortRedirectProtocol;

/// Default for --metrics-listen, next to the client's default, so both can run on one host.
pub const DEFAULT_METRICS_LISTEN: &str = "127.0.0.1:9899";

/// Default for --max-quic-connections.
pub const DEFAULT_MAX_QUIC_CONNECTIONS: u32 = 64;

/// Options renamed before 1.0, as pairs of old and new names.
const RENAMED_OPTIONS: &[(&str, &str)] = &[
    ("--quic-psk", "--psk"),
    ("--quic-psk-file", "--psk-file"),
    ("--local-host", "--listen-host"),
    ("--quic-server-host", "--quic-listen-host"),
    ("--quic-server-port", "--quic-listen-port"),
];

/// PortRedirect server: listens on the ports its clients ask for and forwards the TCP
/// connections it accepts to the clients through QUIC.
#[derive(Parser, Debug)]
#[command(name = "portredirect_server", version)]
pub struct Args {
    /// TOML file with settings, e.g. a list of clients. Its keys are the names of the options
    /// without the leading dashes, e.g. max-connections = 100. Options given on the command line
    /// or in the environment take precedence.
    #[clap(long, value_name = "PATH", env = "PORTREDIRECT_CONFIG_FILE")]
    pub config_file: Option<PathBuf>,

    /// Full path to configuration directory.
    #[clap(long, value_name = "PATH", env = "PORTREDIRECT_CONFIG_DIR")]
    pub config_dir: Option<PathBuf>,

    /// Host to listen on for external TCP connections, on the ports the clients ask for.
    /// Required, here, in the environment or in the configuration file.
    #[clap(
        long,
        required_unless_present_any = ["config_file", "print_quic_cert_fingerprint"],
        env = "PORTREDIRECT_LISTEN_HOST"
    )]
    pub listen_host: Option<String>,

    /// Allowed ports for clients to request, e.g., "80,443,1000-2000". Required, here, in the
    /// environment or in the configuration file, unless it lists clients with their own ports.
    #[clap(
        long,
        value_delimiter = ',',
        required_unless_present_any = ["config_file", "print_quic_cert_fingerprint"],
        env = "PORTREDIRECT_ALLOWED_CLIENT_PORTS"
    )]
    pub allowed_client_ports: Option<Vec<PortSpec>>,

    /// Host to listen on for QUIC connections from clients.
    #[clap(
        long,
        default_value = "127.0.0.1",
        env = "PORTREDIRECT_QUIC_LISTEN_HOST"
    )]
    pub quic_listen_host: String,

    /// UDP port to listen on for QUIC connections from clients.
    #[clap(long, default_value = "4433", env = "PORTREDIRECT_QUIC_LISTEN_PORT")]
    pub quic_listen_port: u16,

    /// Name the server's generated certificate is issued for (Subject Alt Name). Clients check
    /// it, see their --quic-cert-hostname.
    #[clap(
        long,
        default_value = "127.0.0.1",
        env = "PORTREDIRECT_QUIC_CERT_HOSTNAME"
    )]
    pub quic_cert_hostname: String,

    /// Print the fingerprint of the server's certificate and exit. Clients can trust the
    /// certificate by it, see their --quic-cert-fingerprint. If there is no certificate, generates
    /// one first, e.g. to prepare a new one in another --config-dir.
    #[clap(long)]
    pub print_quic_cert_fingerprint: bool,

    #[command(flatten)]
    pub psk: PskArgs,

    /// Maximum number of concurrent QUIC connections, including connections that are not
    /// authenticated yet. Each client uses one.
    #[clap(
        long,
        default_value_t = DEFAULT_MAX_QUIC_CONNECTIONS,
        value_parser = clap::value_parser!(u32).range(1..),
        env = "PORTREDIRECT_MAX_QUIC_CONNECTIONS"
    )]
    pub max_quic_connections: u32,

    /// Maximum number of concurrently forwarded TCP connections per client.
    /// Further connections wait until one ends.
    #[clap(
        long,
        default_value_t = PortRedirectProtocol::DEFAULT_MAX_FORWARDED_CONNECTIONS as u32,
        value_parser = clap::value_parser!(u32).range(1..),
        env = "PORTREDIRECT_MAX_CONNECTIONS"
    )]
    pub max_connections: u32,

    /// Maximum number of concurrently forwarded TCP connections per external IP address
    /// (IPv6: per /64 network), 0 for no limit. Further connections are closed right away.
    #[clap(
        long,
        default_value_t = ForwardingLimits::DEFAULT_MAX_CONNECTIONS_PER_IP as u32,
        env = "PORTREDIRECT_MAX_CONNECTIONS_PER_IP"
    )]
    pub max_connections_per_ip: u32,

    /// Maximum number of new forwarded TCP connections per second and external IP address
    /// (IPv6: per /64 network), 0 for no limit. Further connections are closed right away.
    #[clap(
        long,
        default_value_t = ForwardingLimits::DEFAULT_MAX_CONNECTION_RATE_PER_IP,
        env = "PORTREDIRECT_MAX_CONNECTION_RATE_PER_IP"
    )]
    pub max_connection_rate_per_ip: u32,

    /// Number of new forwarded TCP connections an external IP address may open at once, before
    /// --max-connection-rate-per-ip applies.
    #[clap(
        long,
        default_value_t = ForwardingLimits::DEFAULT_MAX_CONNECTION_BURST_PER_IP,
        value_parser = clap::value_parser!(u32).range(1..),
        env = "PORTREDIRECT_MAX_CONNECTION_BURST_PER_IP"
    )]
    pub max_connection_burst_per_ip: u32,

    /// Close forwarded TCP connections after this many seconds without data transfer,
    /// 0 to never close idle connections.
    #[clap(
        long,
        default_value_t = ForwardingLimits::DEFAULT_IDLE_TIMEOUT.as_secs(),
        env = "PORTREDIRECT_IDLE_TIMEOUT"
    )]
    pub idle_timeout: u64,

    /// How fast to send to clients. bbr is much faster on links that lose packets for other
    /// reasons than congestion, e.g. wireless ones. Set the clients' option, too, for the other
    /// direction.
    #[clap(
        long,
        value_enum,
        default_value_t = CongestionControl::Cubic,
        env = "PORTREDIRECT_CONGESTION_CONTROL"
    )]
    pub congestion_control: CongestionControl,

    /// Print metrics to stderr every second, if any value changes.
    #[clap(long, env = "PORTREDIRECT_PRINT_METRICS", value_parser = BoolishValueParser::new())]
    pub print_metrics: bool,

    /// Serve Prometheus metrics via HTTP at /metrics, see --metrics-listen.
    #[clap(long, env = "PORTREDIRECT_PROVIDE_METRICS", value_parser = BoolishValueParser::new())]
    pub provide_metrics: bool,

    /// Address and port for --provide-metrics. The endpoint has no authentication, only make it
    /// reachable from trusted networks.
    #[clap(long, default_value = DEFAULT_METRICS_LISTEN, env = "PORTREDIRECT_METRICS_LISTEN")]
    pub metrics_listen: SocketAddr,

    /// Seconds that running forwarded connections may take to finish when shutting down on
    /// SIGINT or SIGTERM, 0 to close them right away. A second signal closes them right away.
    #[clap(
        long,
        default_value_t = DEFAULT_SHUTDOWN_TIMEOUT.as_secs(),
        env = "PORTREDIRECT_SHUTDOWN_TIMEOUT"
    )]
    pub shutdown_timeout: u64,

    /// Log messages up to this level: off, error, warn, info, debug or trace. The RUST_LOG
    /// environment variable, if set, takes precedence and can set levels per module.
    #[clap(long, default_value = "info", env = "PORTREDIRECT_LOG_LEVEL")]
    pub log_level: LevelFilter,

    /// Format of log messages: text, or json, one JSON object per line, e.g. for log collectors.
    #[clap(
        long,
        value_enum,
        default_value_t = LogFormat::Text,
        env = "PORTREDIRECT_LOG_FORMAT"
    )]
    pub log_format: LogFormat,
}

/// The server's configuration file. Its keys are the names of the options; instead of a single
/// client with psk-file and allowed-client-ports, it can list several clients.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ConfigFile {
    pub config_dir: Option<PathBuf>,
    pub listen_host: Option<String>,
    #[serde(default, deserialize_with = "config::optional_ports")]
    pub allowed_client_ports: Option<Vec<PortSpec>>,
    pub quic_listen_host: Option<String>,
    pub quic_listen_port: Option<u16>,
    pub quic_cert_hostname: Option<String>,
    pub psk_file: Option<PathBuf>,
    pub max_quic_connections: Option<NonZeroU32>,
    pub max_connections: Option<NonZeroU32>,
    pub max_connections_per_ip: Option<u32>,
    pub max_connection_rate_per_ip: Option<u32>,
    pub max_connection_burst_per_ip: Option<NonZeroU32>,
    pub idle_timeout: Option<u64>,
    pub congestion_control: Option<CongestionControl>,
    pub print_metrics: Option<bool>,
    pub provide_metrics: Option<bool>,
    pub metrics_listen: Option<SocketAddr>,
    pub shutdown_timeout: Option<u64>,
    #[serde(default, deserialize_with = "config::optional_parsed")]
    pub log_level: Option<LevelFilter>,
    pub log_format: Option<LogFormat>,
    pub clients: Option<Vec<ConfiguredClient>>,
}

impl ConfigFile {
    /// Reads the configuration file at `path`. Relative paths in it are relative to its
    /// directory.
    pub fn read(path: &Path) -> Result<Self> {
        let mut file: Self = read_config_file(path)?;
        let psk_files = file
            .clients
            .iter_mut()
            .flatten()
            .flat_map(|client| client.psk_files.iter_mut());
        for relative in file
            .config_dir
            .iter_mut()
            .chain(file.psk_file.iter_mut())
            .chain(psk_files)
        {
            *relative = resolve_path(path, relative);
        }
        Ok(file)
    }
}

/// A client in the server's configuration file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ConfiguredClient {
    /// The name the client authenticates with.
    #[serde(deserialize_with = "config::parsed")]
    pub name: ClientName,
    /// Files with the client's PSK, or with two while changing it.
    pub psk_files: Vec<PathBuf>,
    /// The ports the client may ask the server to listen on.
    #[serde(deserialize_with = "config::ports")]
    pub ports: Vec<PortSpec>,
}

/// The server's configuration, from the command line, the environment and the configuration
/// file, in this order of precedence.
#[derive(Debug)]
pub struct Config {
    pub config_file: Option<PathBuf>,
    pub config_dir: Option<PathBuf>,
    pub listen_host: String,
    pub quic_listen_host: String,
    pub quic_listen_port: u16,
    pub quic_cert_hostname: String,
    pub clients: Clients,
    pub max_quic_connections: usize,
    pub forwarding_limits: ForwardingLimits,
    pub congestion_control: CongestionControl,
    pub print_metrics: bool,
    /// Address to serve Prometheus metrics on, if any.
    pub metrics_addr: Option<SocketAddr>,
    /// How long running forwarded connections may take to finish when shutting down.
    pub shutdown_timeout: Duration,
    pub log_level: LevelFilter,
    pub log_format: LogFormat,
}

/// The clients the server accepts, before their PSKs are read.
#[derive(Debug)]
pub enum Clients {
    /// A single client, named [`ClientName::DEFAULT`], configured with a PSK and
    /// allowed-client-ports.
    Single {
        psk: PskSource,
        ports: Vec<PortSpec>,
    },
    /// The clients listed in the configuration file.
    List(Vec<ConfiguredClient>),
}

impl Clients {
    /// Reads the PSKs and returns the clients.
    pub fn load(&self) -> Result<ClientList> {
        match self {
            Self::Single { psk, ports } => Ok(ClientList::single(psk.load()?, ports.clone())),
            Self::List(clients) => {
                let mut entries = Vec::with_capacity(clients.len());
                for client in clients {
                    let psks = client
                        .psk_files
                        .iter()
                        .map(|path| PskSource::File(path.clone()).load())
                        .collect::<Result<_>>()?;
                    entries.push(ClientEntry {
                        name: client.name.clone(),
                        psks,
                        ports: client.ports.clone(),
                    });
                }
                ClientList::new(entries)
            }
        }
    }
}

/// What the server program does.
#[derive(Debug)]
pub enum Command {
    /// Runs the server.
    Run(Box<Config>),
    /// Prints the fingerprint of the server's certificate, see --print-quic-cert-fingerprint.
    PrintFingerprint(CertificateConfig),
}

/// The settings for --print-quic-cert-fingerprint.
#[derive(Debug)]
pub struct CertificateConfig {
    pub config_dir: Option<PathBuf>,
    pub quic_cert_hostname: String,
    pub log_level: LevelFilter,
    pub log_format: LogFormat,
}

impl Command {
    /// Returns what the program's command line, the environment and the configuration file ask
    /// for, and the parsed command line, e.g. to read the configuration file again. Exits with
    /// code 2 if they are invalid, like for invalid arguments.
    pub fn from_command_line() -> (Self, ArgMatches) {
        let renamed = check_renamed_options(std::env::args_os().skip(1), RENAMED_OPTIONS)
            .and_then(|()| check_renamed_environment());
        if let Err(e) = renamed {
            Args::command()
                .error(ErrorKind::UnknownArgument, e.to_string())
                .exit()
        }
        let matches = Args::command().get_matches();
        let command = Self::from_matches(&matches).unwrap_or_else(|e| {
            Args::command()
                .error(ErrorKind::InvalidValue, format!("{:#}", e).trim_end())
                .exit()
        });
        (command, matches)
    }

    /// Returns what the command-line `matches`, the environment and the configuration file ask
    /// for.
    pub fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let args = Args::from_arg_matches(matches)?;
        let file = match &args.config_file {
            Some(path) => ConfigFile::read(path)?,
            None => ConfigFile::default(),
        };
        if args.print_quic_cert_fingerprint {
            // The server doesn't run, so it needs no clients.
            return Ok(Self::PrintFingerprint(CertificateConfig {
                config_dir: merge_option(matches, "config_dir", args.config_dir, file.config_dir),
                quic_cert_hostname: merge(
                    matches,
                    "quic_cert_hostname",
                    args.quic_cert_hostname,
                    file.quic_cert_hostname,
                ),
                log_level: merge(matches, "log_level", args.log_level, file.log_level),
                log_format: merge(matches, "log_format", args.log_format, file.log_format),
            }));
        }
        Config::from_args(matches, args, file).map(|config| Self::Run(Box::new(config)))
    }
}

impl Config {
    /// Returns the configuration given by the command-line `matches`, parsed into `args`, the
    /// environment and the configuration `file`.
    fn from_args(matches: &ArgMatches, args: Args, file: ConfigFile) -> Result<Self> {
        let psk = args.psk.source(matches);
        let clients = match file.clients {
            Some(clients) => {
                // Each client has its own PSKs and ports, so these settings would be ambiguous.
                let single_client_setting = if psk.is_some() {
                    Some(String::from(
                        "a PSK on the command line or in the environment",
                    ))
                } else if args.allowed_client_ports.is_some() {
                    Some("--allowed-client-ports".into())
                } else if file.psk_file.is_some() {
                    Some("psk-file".into())
                } else if file.allowed_client_ports.is_some() {
                    Some("allowed-client-ports".into())
                } else {
                    None
                };
                if let Some(setting) = single_client_setting {
                    bail!(
                        "the configuration file lists clients with their own PSK files and ports, so {} doesn't apply",
                        setting
                    );
                }
                check_clients(&clients)?;
                Clients::List(clients)
            }
            None => {
                let psk = psk
                    .or(file.psk_file.map(PskSource::File))
                    .ok_or_else(|| {
                        anyhow!(
                            "a pre-shared key is required: use --psk-file, {}, --psk, or psk-file in the configuration file",
                            PSK_ENV_VAR
                        )
                    })?;
                let ports = merge_option(
                    matches,
                    "allowed_client_ports",
                    args.allowed_client_ports,
                    file.allowed_client_ports,
                );
                Clients::Single {
                    psk,
                    ports: required(ports, "allowed-client-ports")?,
                }
            }
        };

        let listen_host = merge_option(matches, "listen_host", args.listen_host, file.listen_host);
        let max_quic_connections = merge(
            matches,
            "max_quic_connections",
            args.max_quic_connections,
            file.max_quic_connections.map(NonZeroU32::get),
        );
        let max_connections = merge(
            matches,
            "max_connections",
            args.max_connections,
            file.max_connections.map(NonZeroU32::get),
        );
        let max_connections_per_ip = merge(
            matches,
            "max_connections_per_ip",
            args.max_connections_per_ip,
            file.max_connections_per_ip,
        );
        let max_connection_rate_per_ip = merge(
            matches,
            "max_connection_rate_per_ip",
            args.max_connection_rate_per_ip,
            file.max_connection_rate_per_ip,
        );
        let max_connection_burst_per_ip = merge(
            matches,
            "max_connection_burst_per_ip",
            args.max_connection_burst_per_ip,
            file.max_connection_burst_per_ip.map(NonZeroU32::get),
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
        let idle_timeout = merge(
            matches,
            "idle_timeout",
            args.idle_timeout,
            file.idle_timeout,
        );
        Ok(Config {
            config_dir: merge_option(matches, "config_dir", args.config_dir, file.config_dir),
            listen_host: required(listen_host, "listen-host")?,
            quic_listen_host: merge(
                matches,
                "quic_listen_host",
                args.quic_listen_host,
                file.quic_listen_host,
            ),
            quic_listen_port: merge(
                matches,
                "quic_listen_port",
                args.quic_listen_port,
                file.quic_listen_port,
            ),
            quic_cert_hostname: merge(
                matches,
                "quic_cert_hostname",
                args.quic_cert_hostname,
                file.quic_cert_hostname,
            ),
            clients,
            max_quic_connections: max_quic_connections as usize,
            forwarding_limits: ForwardingLimits {
                max_connections: max_connections as usize,
                max_connections_per_ip: max_connections_per_ip as usize,
                max_connection_rate_per_ip,
                max_connection_burst_per_ip,
                idle_timeout: (idle_timeout > 0).then(|| Duration::from_secs(idle_timeout)),
            },
            congestion_control: merge(
                matches,
                "congestion_control",
                args.congestion_control,
                file.congestion_control,
            ),
            print_metrics: merge(
                matches,
                "print_metrics",
                args.print_metrics,
                file.print_metrics,
            ),
            metrics_addr: provide_metrics.then_some(metrics_listen),
            shutdown_timeout: Duration::from_secs(merge(
                matches,
                "shutdown_timeout",
                args.shutdown_timeout,
                file.shutdown_timeout,
            )),
            log_level: merge(matches, "log_level", args.log_level, file.log_level),
            log_format: merge(matches, "log_format", args.log_format, file.log_format),
            config_file: args.config_file,
        })
    }
}

/// Checks the clients listed in the configuration file, before their PSKs are read, see
/// [`ClientList::new`].
fn check_clients(clients: &[ConfiguredClient]) -> Result<()> {
    if clients.is_empty() {
        bail!("the list of clients in the configuration file is empty");
    }
    let mut names = BTreeSet::new();
    for client in clients {
        let name = client.name.as_str();
        if !names.insert(name) {
            bail!("client {:?} is listed twice", name);
        }
        let count = client.psk_files.len();
        if !(1..=MAX_PSKS_PER_CLIENT).contains(&count) {
            bail!(
                "client {:?} has {} PSK files, it needs one, or two while changing its PSK",
                name,
                count
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::examples;
    use crate::server::AllowedPorts;
    use secrecy::ExposeSecret;
    use std::fs;

    #[test]
    fn test_example_is_valid_and_has_every_setting() -> Result<()> {
        let path = examples::path("server.toml");
        // Valid as it is, ...
        let config = config(&["--config-file", path.to_str().unwrap()])?;
        assert!(matches!(&config.clients, Clients::List(clients) if clients.len() == 3));
        // ... and with the settings that are commented out, which show the defaults.
        let text = fs::read_to_string(&path)?;
        let dir = tempfile::tempdir()?;
        let uncommented = dir.path().join("server.toml");
        fs::write(&uncommented, examples::uncommented(&text))?;
        let file = ConfigFile::read(&uncommented)?;
        assert_eq!(
            file.max_quic_connections.map(NonZeroU32::get),
            Some(DEFAULT_MAX_QUIC_CONNECTIONS)
        );
        assert_eq!(file.log_level, Some(LevelFilter::INFO));
        // Every option that a configuration file can have is in it.
        let missing = examples::missing_options(
            &Args::command(),
            &text,
            &["config-file", "psk", "print-quic-cert-fingerprint"],
        );
        assert!(
            missing.is_empty(),
            "examples/server.toml lacks {:?}",
            missing
        );
        Ok(())
    }

    /// Returns what the command-line `args` ask for.
    fn command(args: &[&str]) -> Result<Command> {
        let matches =
            Args::command().try_get_matches_from(["portredirect_server"].iter().chain(args))?;
        Command::from_matches(&matches)
    }

    /// Returns the configuration given by the command-line `args`.
    fn config(args: &[&str]) -> Result<Config> {
        match command(args)? {
            Command::Run(config) => Ok(*config),
            Command::PrintFingerprint(_) => bail!("prints the fingerprint instead of running"),
        }
    }

    /// Returns the configuration given by the command-line `args` and a configuration file with
    /// `text`, which is in `dir` as `server.toml`.
    fn config_with_file(dir: &Path, text: &str, args: &[&str]) -> Result<Config> {
        let path = dir.join("server.toml");
        fs::write(&path, text)?;
        let mut args = args.to_vec();
        args.extend(["--config-file", path.to_str().unwrap()]);
        config(&args)
    }

    fn error_with_file(text: &str, args: &[&str]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let err = config_with_file(dir.path(), text, args).unwrap_err();
        format!("{:#}", err)
    }

    const FILE: &str = r#"
        config-dir = "state"
        listen-host = "0.0.0.0"
        allowed-client-ports = [443, "8000-8100"]
        quic-listen-host = "::"
        quic-listen-port = 4434
        quic-cert-hostname = "tunnel.example.com"
        psk-file = "psk"
        max-quic-connections = 10
        max-connections = 20
        max-connections-per-ip = 0
        max-connection-rate-per-ip = 0
        max-connection-burst-per-ip = 5
        idle-timeout = 0
        congestion-control = "bbr"
        print-metrics = true
        provide-metrics = true
        metrics-listen = "127.0.0.1:9999"
        shutdown-timeout = 30
        log-level = "debug"
        log-format = "json"
    "#;

    #[test]
    fn test_command_line_with_defaults() -> Result<()> {
        let config = config(&[
            "--listen-host",
            "127.0.0.1",
            "--allowed-client-ports",
            "443,8000-8100",
            "--psk-file",
            "/etc/portredirect/psk",
        ])?;
        assert!(config.config_file.is_none() && config.config_dir.is_none());
        assert_eq!(config.listen_host, "127.0.0.1");
        assert_eq!(config.quic_listen_host, "127.0.0.1");
        assert_eq!(config.quic_listen_port, 4433);
        assert_eq!(config.quic_cert_hostname, "127.0.0.1");
        match &config.clients {
            Clients::Single {
                psk: PskSource::File(path),
                ports,
            } => {
                assert_eq!(path, Path::new("/etc/portredirect/psk"));
                assert!(ports.allows(443) && ports.allows(8050) && !ports.allows(80));
            }
            other => panic!("{:?}", other),
        }
        assert_eq!(config.max_quic_connections, 64);
        assert_eq!(config.forwarding_limits, ForwardingLimits::default());
        assert_eq!(config.congestion_control, CongestionControl::Cubic);
        assert!(!config.print_metrics);
        assert_eq!(config.metrics_addr, None);
        assert_eq!(config.shutdown_timeout, DEFAULT_SHUTDOWN_TIMEOUT);
        assert_eq!(config.log_level, LevelFilter::INFO);
        assert_eq!(config.log_format, LogFormat::Text);
        Ok(())
    }

    #[test]
    fn test_configuration_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = config_with_file(dir.path(), FILE, &[])?;

        assert_eq!(config.config_file, Some(dir.path().join("server.toml")));
        // Relative to the file's directory.
        assert_eq!(config.config_dir, Some(dir.path().join("state")));
        assert_eq!(config.listen_host, "0.0.0.0");
        assert_eq!(config.quic_listen_host, "::");
        assert_eq!(config.quic_listen_port, 4434);
        assert_eq!(config.quic_cert_hostname, "tunnel.example.com");
        match &config.clients {
            Clients::Single {
                psk: PskSource::File(path),
                ports,
            } => {
                assert_eq!(path, &dir.path().join("psk"));
                assert!(ports.allows(443) && ports.allows(8100) && !ports.allows(80));
            }
            other => panic!("{:?}", other),
        }
        assert_eq!(config.max_quic_connections, 10);
        assert_eq!(
            config.forwarding_limits,
            ForwardingLimits {
                max_connections: 20,
                max_connections_per_ip: 0,
                max_connection_rate_per_ip: 0,
                max_connection_burst_per_ip: 5,
                idle_timeout: None,
            }
        );
        assert_eq!(config.congestion_control, CongestionControl::Bbr);
        assert!(config.print_metrics);
        assert_eq!(config.metrics_addr, Some("127.0.0.1:9999".parse()?));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
        assert_eq!(config.log_level, LevelFilter::DEBUG);
        assert_eq!(config.log_format, LogFormat::Json);
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
                "--listen-host",
                "127.0.0.1",
                "--allowed-client-ports",
                "80",
                "--quic-listen-host",
                "127.0.0.2",
                "--quic-listen-port",
                "4433",
                "--quic-cert-hostname",
                "localhost",
                "--psk",
                "secret",
                "--max-quic-connections",
                "30",
                "--max-connections",
                "40",
                "--max-connections-per-ip",
                "50",
                "--max-connection-rate-per-ip",
                "7",
                "--max-connection-burst-per-ip",
                "8",
                "--idle-timeout",
                "60",
                "--congestion-control",
                "cubic",
                "--metrics-listen",
                DEFAULT_METRICS_LISTEN,
                "--shutdown-timeout",
                "0",
                "--log-level",
                "warn",
                "--log-format",
                "text",
            ],
        )?;

        assert_eq!(config.config_dir, Some("/var/lib/portredirect".into()));
        assert_eq!(config.listen_host, "127.0.0.1");
        assert_eq!(config.quic_listen_host, "127.0.0.2");
        // Overrides the file, though it is the default.
        assert_eq!(config.quic_listen_port, 4433);
        assert_eq!(config.quic_cert_hostname, "localhost");
        match &config.clients {
            Clients::Single {
                psk: psk @ PskSource::CommandLine(_),
                ports,
            } => {
                assert_eq!(psk.load()?.expose_secret(), "secret");
                assert!(ports.allows(80) && !ports.allows(443));
            }
            other => panic!("{:?}", other),
        }
        assert_eq!(config.max_quic_connections, 30);
        assert_eq!(
            config.forwarding_limits,
            ForwardingLimits {
                max_connections: 40,
                max_connections_per_ip: 50,
                max_connection_rate_per_ip: 7,
                max_connection_burst_per_ip: 8,
                idle_timeout: Some(Duration::from_secs(60)),
            }
        );
        // Overrides the file, though it is the default.
        assert_eq!(config.congestion_control, CongestionControl::Cubic);
        // A flag can only switch a setting on.
        assert!(config.print_metrics);
        // Overrides the file, though it is the default.
        assert_eq!(config.metrics_addr, Some(DEFAULT_METRICS_LISTEN.parse()?));
        assert_eq!(config.shutdown_timeout, Duration::ZERO);
        assert_eq!(config.log_level, LevelFilter::WARN);
        assert_eq!(config.log_format, LogFormat::Text);

        let config = config_with_file(
            dir.path(),
            "print-metrics = false",
            &[
                "--listen-host",
                "127.0.0.1",
                "--allowed-client-ports",
                "80",
                "--psk",
                "secret",
                "--print-metrics",
            ],
        )?;
        assert!(config.print_metrics);
        Ok(())
    }

    #[test]
    fn test_clients_from_configuration_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::create_dir(dir.path().join("clients"))?;
        for (file, psk) in [
            ("clients/home.psk", "home-psk-0123456789"),
            ("clients/office.psk", "office-psk-0123456789"),
            ("clients/office-next.psk", "office-next-psk-0123456789"),
        ] {
            fs::write(dir.path().join(file), psk)?;
        }
        let config = config_with_file(
            dir.path(),
            r#"
                listen-host = "0.0.0.0"

                [[clients]]
                name = "home"
                psk-files = ["clients/home.psk"]
                ports = "443, 8443"

                [[clients]]
                name = "office"
                psk-files = ["clients/office.psk", "clients/office-next.psk"]
                ports = [8000]
            "#,
            &[],
        )?;

        let Clients::List(configured) = &config.clients else {
            panic!("{:?}", config.clients);
        };
        assert_eq!(configured.len(), 2);
        assert_eq!(
            configured[1].psk_files,
            [
                dir.path().join("clients/office.psk"),
                dir.path().join("clients/office-next.psk")
            ]
        );

        let clients = config.clients.load()?;
        assert_eq!(clients.len(), 2);
        let home = clients.get(&"home".parse().unwrap()).unwrap();
        assert!(home.ports.allows(8443) && !home.ports.allows(8000));
        assert_eq!(home.psks[0].expose_secret(), "home-psk-0123456789");
        let office = clients.get(&"office".parse().unwrap()).unwrap();
        assert!(office.ports.allows(8000) && !office.ports.allows(443));
        let psks: Vec<&str> = office.psks.iter().map(|psk| psk.expose_secret()).collect();
        assert_eq!(
            psks,
            ["office-psk-0123456789", "office-next-psk-0123456789"]
        );
        Ok(())
    }

    #[test]
    fn test_every_option_has_an_environment_variable() {
        for arg in Args::command().get_arguments() {
            // The programs take options only.
            let option = arg.get_long().unwrap();
            // A command rather than a setting: in the environment, the server would never run.
            let expected =
                (option != "print-quic-cert-fingerprint").then(|| config::env_var_name(option));
            assert_eq!(
                arg.get_env().and_then(|env| env.to_str()),
                expected.as_deref(),
                "--{}",
                option
            );
        }
    }

    #[test]
    fn test_clients_exclude_settings_of_a_single_client() {
        let clients = "listen-host = \"0.0.0.0\"\n[[clients]]\nname = \"home\"\npsk-files = [\"home.psk\"]\nports = 443\n";
        for (text, args, expected) in [
            (
                clients.to_string(),
                &["--psk", "secret"][..],
                "so a PSK on the command line or in the environment doesn't apply",
            ),
            (
                clients.to_string(),
                &["--psk-file", "psk"],
                "so a PSK on the command line or in the environment doesn't apply",
            ),
            (
                clients.to_string(),
                &["--allowed-client-ports", "443"],
                "so --allowed-client-ports doesn't apply",
            ),
            (
                format!("psk-file = \"psk\"\n{}", clients),
                &[],
                "so psk-file doesn't apply",
            ),
            (
                format!("allowed-client-ports = 443\n{}", clients),
                &[],
                "so allowed-client-ports doesn't apply",
            ),
        ] {
            let message = error_with_file(&text, args);
            assert!(message.contains(expected), "{:?}: {}", args, message);
        }
    }

    #[test]
    fn test_log_format_must_be_known() {
        let message = error_with_file("log-format = \"xml\"", &[]);
        assert!(message.contains("unknown variant `xml`"), "{}", message);
        let args = [
            "--listen-host",
            "::",
            "--psk",
            "secret",
            "--log-format",
            "xml",
        ];
        let err = config(&args)
            .unwrap_err()
            .downcast::<clap::Error>()
            .unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn test_congestion_control_must_be_known() {
        let message = error_with_file("congestion-control = \"reno\"", &[]);
        assert!(message.contains("unknown variant `reno`"), "{}", message);
        let args = [
            "--listen-host",
            "::",
            "--allowed-client-ports",
            "443",
            "--psk",
            "secret",
            "--congestion-control",
            "reno",
        ];
        let err = config(&args)
            .unwrap_err()
            .downcast::<clap::Error>()
            .unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn test_connection_burst_is_at_least_one() {
        let message = error_with_file("max-connection-burst-per-ip = 0", &[]);
        assert!(message.contains("nonzero"), "{}", message);
        let args = [
            "--listen-host",
            "::",
            "--allowed-client-ports",
            "443",
            "--psk",
            "secret",
            "--max-connection-burst-per-ip",
            "0",
        ];
        let err = config(&args)
            .unwrap_err()
            .downcast::<clap::Error>()
            .unwrap();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn test_invalid_clients_are_rejected() {
        let client = |name: &str, psk_files: &str| {
            format!(
                "[[clients]]\nname = \"{}\"\npsk-files = {}\nports = 443\n",
                name, psk_files
            )
        };
        let two_homes = format!(
            "{}{}",
            client("home", r#"["a.psk"]"#),
            client("home", r#"["b.psk"]"#)
        );
        for (clients, expected) in [
            (
                "clients = []".to_string(),
                "the list of clients in the configuration file is empty",
            ),
            (two_homes, "client \"home\" is listed twice"),
            (client("home", "[]"), "client \"home\" has 0 PSK files"),
            (
                client("home", r#"["a", "b", "c"]"#),
                "client \"home\" has 3 PSK files, it needs one, or two while changing its PSK",
            ),
            (
                client("my home", r#"["a"]"#),
                "invalid client name \"my home\"",
            ),
            (
                "[[clients]]\nname = \"home\"\npsk-file = \"a\"\nports = 443\n".into(),
                "unknown field `psk-file`, expected one of `name`, `psk-files`, `ports`",
            ),
            (
                "[[clients]]\nname = \"home\"\npsk-files = [\"a\"]\n".into(),
                "missing field `ports`",
            ),
            (
                "[[clients]]\nname = \"home\"\npsk-files = [\"a\"]\nports = []\n".into(),
                "no ports given",
            ),
        ] {
            let message = error_with_file(&format!("listen-host = \"::\"\n{}", clients), &[]);
            assert!(message.contains(expected), "{:?}: {}", clients, message);
        }
    }

    #[test]
    fn test_psks_are_only_read_from_files() {
        // So the configuration file holds no secrets.
        for (text, expected) in [
            ("psk = \"secret\"", "unknown field `psk`"),
            (
                "[[clients]]\nname = \"home\"\npsks = [\"secret\"]\nports = 443\n",
                "unknown field `psks`",
            ),
        ] {
            let message = error_with_file(text, &[]);
            assert!(message.contains(expected), "{:?}: {}", text, message);
        }
    }

    #[test]
    fn test_required_settings() {
        for (text, expected) in [
            (
                "allowed-client-ports = 443\npsk-file = \"psk\"",
                "--listen-host is required, on the command line, as PORTREDIRECT_LISTEN_HOST in the environment or as listen-host in the configuration file",
            ),
            (
                "listen-host = \"::\"\npsk-file = \"psk\"",
                "--allowed-client-ports is required",
            ),
            (
                "listen-host = \"::\"\nallowed-client-ports = 443",
                "a pre-shared key is required: use --psk-file, PORTREDIRECT_PSK, --psk, or psk-file in the configuration file",
            ),
        ] {
            let message = error_with_file(text, &[]);
            assert!(message.contains(expected), "{:?}: {}", text, message);
        }
        // Without configuration file, clap requires them.
        let err = config(&["--psk", "secret"]).unwrap_err();
        let err = err.downcast::<clap::Error>().unwrap();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn test_unreadable_psk_files_fail_to_load() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let listed = config_with_file(
            dir.path(),
            "listen-host = \"::\"\n[[clients]]\nname = \"home\"\npsk-files = [\"home.psk\"]\nports = 443\n",
            &[],
        )?;
        let err = listed.clients.load().unwrap_err();
        assert!(
            err.to_string().contains("failed to read PSK file"),
            "{:#}",
            err
        );

        let single = config(&[
            "--listen-host",
            "::",
            "--allowed-client-ports",
            "443",
            "--psk",
            "",
        ])?;
        assert!(single.clients.load().is_err());
        Ok(())
    }

    /// Returns the settings for printing the certificate's fingerprint, given by `args` and a
    /// configuration file with `text`, if any.
    fn certificate_config(text: Option<&str>, args: &[&str]) -> Result<CertificateConfig> {
        let dir = tempfile::tempdir()?;
        let mut args = args.to_vec();
        let path = dir.path().join("server.toml");
        if let Some(text) = text {
            fs::write(&path, text)?;
            args.extend(["--config-file", path.to_str().unwrap()]);
        }
        match command(&args)? {
            Command::PrintFingerprint(config) => Ok(config),
            Command::Run(_) => bail!("runs instead of printing the fingerprint"),
        }
    }

    #[test]
    fn test_printing_the_fingerprint_needs_only_the_certificate_settings() -> Result<()> {
        let print = "--print-quic-cert-fingerprint";
        // No clients, PSK or ports.
        let defaults = certificate_config(None, &[print])?;
        assert_eq!(defaults.config_dir, None);
        assert_eq!(defaults.quic_cert_hostname, "127.0.0.1");
        assert_eq!(defaults.log_level, LevelFilter::INFO);
        let err = config(&[print]).unwrap_err();
        assert_eq!(err.to_string(), "prints the fingerprint instead of running");

        let from_file = certificate_config(Some(FILE), &[print])?;
        assert!(from_file.config_dir.unwrap().ends_with("state"));
        assert_eq!(from_file.quic_cert_hostname, "tunnel.example.com");
        assert_eq!(from_file.log_level, LevelFilter::DEBUG);

        let args = [
            print,
            "--config-dir",
            "/var/lib/portredirect",
            "--quic-cert-hostname",
            "localhost",
            "--log-level",
            "warn",
        ];
        let overridden = certificate_config(Some(FILE), &args)?;
        assert_eq!(overridden.config_dir, Some("/var/lib/portredirect".into()));
        assert_eq!(overridden.quic_cert_hostname, "localhost");
        assert_eq!(overridden.log_level, LevelFilter::WARN);

        // Without the option, the server runs.
        let err = certificate_config(Some(FILE), &[]).unwrap_err();
        assert_eq!(err.to_string(), "runs instead of printing the fingerprint");
        Ok(())
    }

    #[test]
    fn test_missing_configuration_file_is_an_error() {
        let err = config(&["--config-file", "/nonexistent/server.toml"]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "failed to read the configuration file /nonexistent/server.toml"
        );
    }
}
