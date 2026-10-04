// PortRedirect Server - Reloading the configuration on SIGHUP
//
// On SIGHUP, the server reads its configuration file and the PSK files again, with the command
// line and the environment it started with, and applies what can change while it runs: the
// clients with their PSKs and ports, the limits and the log level. Tunnels that the new
// configuration no longer accepts are closed, the others go on. If the new configuration is
// invalid, nothing of it is applied.
//
// License: GPL-3.0-only

use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use secrecy::ExposeSecret;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::level_filters::LevelFilter;
use tracing::{info, warn};

use crate::app_data::ServerAppData;
use crate::limits::QuicAdmission;
use crate::logging::{self, LogFormat};
use crate::protocol::close::CloseCode;
use crate::quic::server::ConnectionLimit;
use crate::quic::CongestionControl;
use crate::server::clients::{ClientList, Credentials};
use crate::server::config::{Command, Config};
use crate::server::metrics::METRICS;
use crate::server::{AllowedPorts, ForwardingLimits};

/// The settings a reload of the configuration can change.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The clients the server accepts, with their PSKs and ports.
    pub clients: ClientList,
    /// Limits for the connections forwarded for each client. A tunnel keeps the limits it was
    /// set up with.
    pub forwarding_limits: ForwardingLimits,
}

impl Settings {
    /// Returns why these settings no longer accept the tunnel of the client with `credentials` on
    /// `port`, if they don't.
    pub fn revocation(&self, credentials: &Credentials, port: u16) -> Option<Revocation> {
        let Some(client) = self.clients.get(&credentials.name) else {
            return Some(Revocation::ClientRemoved);
        };
        let psk = credentials.psk.expose_secret();
        if !client.psks.iter().any(|known| known.expose_secret() == psk) {
            return Some(Revocation::PskRemoved);
        }
        if !client.ports.allows(port) {
            return Some(Revocation::PortNotAllowed);
        }
        None
    }
}

/// Why a reload of the configuration ended a tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation {
    /// The client is no longer in the configuration.
    ClientRemoved,
    /// The PSK the client authenticated with is no longer one of its PSKs.
    PskRemoved,
    /// The client may no longer use the tunnel's port.
    PortNotAllowed,
}

impl Revocation {
    /// Returns the code to close the tunnel's connection with. Like for a rejected client, the
    /// client doesn't connect again, which would fail the same way.
    pub fn close_code(self) -> CloseCode {
        match self {
            Revocation::ClientRemoved | Revocation::PskRemoved => CloseCode::AuthenticationFailed,
            Revocation::PortNotAllowed => CloseCode::PortNotAllowed,
        }
    }
}

impl fmt::Display for Revocation {
    /// Writes the reason, which the client is told, too.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Revocation::ClientRemoved => "the client was removed from the server's configuration",
            Revocation::PskRemoved => {
                "the client's PSK was removed from the server's configuration"
            }
            Revocation::PortNotAllowed => "the client may no longer use the port",
        })
    }
}

/// The settings that only change with a restart, so a reload names them if they changed.
#[derive(Debug, PartialEq)]
pub struct RestartSettings {
    config_dir: Option<PathBuf>,
    listen_host: String,
    quic_listen_host: String,
    quic_listen_port: u16,
    quic_cert_hostname: String,
    congestion_control: CongestionControl,
    print_metrics: bool,
    metrics_addr: Option<SocketAddr>,
    shutdown_timeout: Duration,
    log_format: LogFormat,
}

impl RestartSettings {
    pub fn of(config: &Config) -> Self {
        Self {
            config_dir: config.config_dir.clone(),
            listen_host: config.listen_host.clone(),
            quic_listen_host: config.quic_listen_host.clone(),
            quic_listen_port: config.quic_listen_port,
            quic_cert_hostname: config.quic_cert_hostname.clone(),
            congestion_control: config.congestion_control,
            print_metrics: config.print_metrics,
            metrics_addr: config.metrics_addr,
            shutdown_timeout: config.shutdown_timeout,
            log_format: config.log_format,
        }
    }

    /// Returns the options whose settings differ in `new`.
    fn changes(&self, new: &Self) -> Vec<&'static str> {
        let mut changed = Vec::new();
        if self.config_dir != new.config_dir {
            changed.push("config-dir");
        }
        if self.listen_host != new.listen_host {
            changed.push("listen-host");
        }
        if self.quic_listen_host != new.quic_listen_host {
            changed.push("quic-listen-host");
        }
        if self.quic_listen_port != new.quic_listen_port {
            changed.push("quic-listen-port");
        }
        if self.quic_cert_hostname != new.quic_cert_hostname {
            changed.push("quic-cert-hostname");
        }
        if self.congestion_control != new.congestion_control {
            changed.push("congestion-control");
        }
        if self.print_metrics != new.print_metrics {
            changed.push("print-metrics");
        }
        if self.metrics_addr != new.metrics_addr {
            changed.push("provide-metrics and metrics-listen");
        }
        if self.shutdown_timeout != new.shutdown_timeout {
            changed.push("shutdown-timeout");
        }
        if self.log_format != new.log_format {
            changed.push("log-format");
        }
        changed
    }
}

/// Reloads the server's configuration, see the module's description.
pub struct Reloader {
    /// The command line, with the environment, the server started with.
    matches: ArgMatches,
    /// The settings the server started with that only change with a restart.
    running: RestartSettings,
    log_level: LevelFilter,
    app_data: ServerAppData,
    connection_limit: ConnectionLimit,
    admission: Arc<QuicAdmission>,
}

impl Reloader {
    /// Returns a reloader for the server started with the command-line `matches`, whose settings
    /// that only change with a restart are `running`, with the log level `log_level`, and which
    /// keeps the settings a reload changes in `app_data` and `connection_limit`. A reload lifts
    /// the blocks of `admission`, as the new configuration may fix what failed.
    pub fn new(
        matches: ArgMatches,
        running: RestartSettings,
        log_level: LevelFilter,
        app_data: ServerAppData,
        connection_limit: ConnectionLimit,
        admission: Arc<QuicAdmission>,
    ) -> Self {
        Self {
            matches,
            running,
            log_level,
            app_data,
            connection_limit,
            admission,
        }
    }

    /// Reads the configuration again and applies what can change while the server runs. If it
    /// is invalid, e.g. a PSK file is missing, applies nothing and fails.
    pub fn reload(&mut self) -> Result<()> {
        // Everything that can fail comes first, so nothing is applied halfway.
        let config = read_config(&self.matches)?;
        let clients = config
            .clients
            .load()
            .context("failed to read the clients' PSKs")?;

        let new = Settings {
            clients,
            forwarding_limits: config.forwarding_limits,
        };
        for name in new.clients.names() {
            // So the metrics of new clients are listed before they connect, too.
            METRICS.client(name);
        }
        let old = self.app_data.update(new.clone());
        log_changes(&old, &new);

        let max_quic_connections = config.max_quic_connections;
        if self.connection_limit.get() != Some(max_quic_connections) {
            self.connection_limit.set(Some(max_quic_connections));
            info!(
                "At most {} QUIC connections from now on (--max-quic-connections)",
                max_quic_connections
            );
        }
        if config.log_level != self.log_level {
            self.log_level = config.log_level;
            match logging::set_log_level(config.log_level, false) {
                Ok(()) => info!(
                    "Logging messages up to the level {} from now on",
                    config.log_level
                ),
                Err(e) => warn!("Not changing the log level: {}", e),
            }
        }

        // E.g. after a client failed to authenticate because the server didn't know it yet.
        let unblocked = self.admission.forget_failures();
        if unblocked > 0 {
            info!(
                "Lifted the blocks of addresses after failed attempts: {}",
                unblocked
            );
        }

        let ignored = self
            .running
            .changes(&RestartSettings::of(&config))
            .join(", ");
        if !ignored.is_empty() {
            warn!(
                "Not applying the changes of {}, they take effect when the server restarts",
                ignored
            );
        }
        info!("Reloaded the configuration");
        Ok(())
    }

    /// Reloads the configuration on each SIGHUP from now on, until the program ends.
    pub fn reload_on_sighup(mut self) {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            // Listening right away, a SIGHUP doesn't end the program any more.
            let hangups = signal(SignalKind::hangup())
                .inspect_err(|e| warn!("Can't reload the configuration on SIGHUP: {}", e));
            if let Ok(mut hangups) = hangups {
                tokio::spawn(async move {
                    while hangups.recv().await.is_some() {
                        info!("Received SIGHUP, reloading the configuration");
                        if let Err(e) = self.reload() {
                            tracing::error!(
                                "Failed to reload the configuration, the current one stays in effect: {:#}",
                                e
                            );
                        }
                    }
                });
            }
        }
        #[cfg(not(unix))]
        let _ = &mut self;
    }
}

/// Returns the configuration that `matches`, the command line, give with the configuration file as
/// it is now.
fn read_config(matches: &ArgMatches) -> Result<Config> {
    match Command::from_matches(matches)? {
        Command::Run(config) => Ok(*config),
        // The server doesn't run then in the first place.
        Command::PrintFingerprint(_) => bail!("the configuration doesn't run the server"),
    }
}

/// Logs how the settings changed from `old` to `new`.
fn log_changes(old: &Settings, new: &Settings) {
    for name in new.clients.names() {
        let client = new.clients.get(name).expect("listed clients exist");
        let Some(old_client) = old.clients.get(name) else {
            info!("Added client {:?}", name.as_str());
            continue;
        };
        let changes = old_client.changes(client).join(" and ");
        if !changes.is_empty() {
            info!("Changed the {} of client {:?}", changes, name.as_str());
        }
    }
    for name in old.clients.names() {
        if new.clients.get(name).is_none() {
            info!("Removed client {:?}", name.as_str());
        }
    }
    let limits = new.forwarding_limits;
    if limits != old.forwarding_limits {
        info!(
            "New limits for the forwarded connections of tunnels set up from now on: at most {} connections, {} per address, {} new ones per second and address after {} at once, idle timeout {:?}",
            limits.max_connections,
            limits.max_connections_per_ip,
            limits.max_connection_rate_per_ip,
            limits.max_connection_burst_per_ip,
            limits.idle_timeout
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::clients::ClientEntry;
    use crate::server::config::Args;
    use crate::tests::collect_logs;
    use clap::CommandFactory;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn client(name: &str, psks: &[&str], port: u16) -> ClientEntry {
        ClientEntry {
            name: name.parse().unwrap(),
            psks: psks.iter().map(|&psk| psk.into()).collect(),
            ports: vec![crate::server::PortSpec::Single(port)],
        }
    }

    fn credentials(name: &str, psk: &str) -> Credentials {
        Credentials {
            name: name.parse().unwrap(),
            psk: psk.into(),
        }
    }

    #[test]
    fn test_tunnels_are_revoked_by_what_they_depend_on() -> Result<()> {
        let settings = Settings {
            clients: ClientList::new([
                client("home", &["old", "new"], 443),
                client("office", &["office"], 80),
            ])?,
            forwarding_limits: ForwardingLimits::default(),
        };
        let revocation = |name, psk, port| settings.revocation(&credentials(name, psk), port);
        // Either PSK of a client, e.g. while it changes, on one of its ports.
        assert_eq!(revocation("home", "old", 443), None);
        assert_eq!(revocation("home", "new", 443), None);
        assert_eq!(
            revocation("lab", "old", 443),
            Some(Revocation::ClientRemoved)
        );
        assert_eq!(
            revocation("home", "office", 443),
            Some(Revocation::PskRemoved)
        );
        assert_eq!(
            revocation("home", "old", 80),
            Some(Revocation::PortNotAllowed)
        );

        // The client doesn't connect again, and learns why.
        for (revocation, close_code, reason) in [
            (
                Revocation::ClientRemoved,
                CloseCode::AuthenticationFailed,
                "the client was removed from the server's configuration",
            ),
            (
                Revocation::PskRemoved,
                CloseCode::AuthenticationFailed,
                "the client's PSK was removed from the server's configuration",
            ),
            (
                Revocation::PortNotAllowed,
                CloseCode::PortNotAllowed,
                "the client may no longer use the port",
            ),
        ] {
            assert_eq!(revocation.close_code(), close_code);
            assert!(close_code.is_permanent());
            assert_eq!(revocation.to_string(), reason);
        }
        Ok(())
    }

    /// A server's configuration file, `server.toml`, and its PSK files, in a temporary directory.
    struct ConfigFiles(tempfile::TempDir);

    impl ConfigFiles {
        fn new() -> Self {
            Self(tempfile::tempdir().unwrap())
        }

        fn path(&self) -> std::path::PathBuf {
            self.0.path().join("server.toml")
        }

        /// Writes the configuration file.
        fn write(&self, config: &str) {
            fs::write(self.path(), config).unwrap();
        }

        /// Writes the PSK file `<name>.psk`, readable by its owner only.
        fn psk(&self, name: &str, psk: &str) {
            let path = self.0.path().join(format!("{}.psk", name));
            write_private(&path, psk);
        }
    }

    fn write_private(path: &Path, content: &str) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// The parts of a server that a reload changes.
    struct Server {
        reloader: Reloader,
        app_data: ServerAppData,
        connection_limit: ConnectionLimit,
        admission: Arc<QuicAdmission>,
    }

    /// Returns a server started with the configuration file `files`, and `args`.
    fn start(files: &ConfigFiles, args: &[&str]) -> Result<Server> {
        let path = files.path();
        let mut command_line = vec![
            "portredirect_server",
            "--config-file",
            path.to_str().unwrap(),
        ];
        command_line.extend(args);
        let matches = Args::command().try_get_matches_from(command_line)?;
        let config = read_config(&matches)?;
        let app_data = ServerAppData::with_clients(config.clients.load()?, "127.0.0.1".into())
            .with_forwarding_limits(config.forwarding_limits);
        let connection_limit = ConnectionLimit::new(Some(config.max_quic_connections));
        let admission = Arc::new(QuicAdmission::default());
        let reloader = Reloader::new(
            matches,
            RestartSettings::of(&config),
            config.log_level,
            app_data.clone(),
            connection_limit.clone(),
            Arc::clone(&admission),
        );
        Ok(Server {
            reloader,
            app_data,
            connection_limit,
            admission,
        })
    }

    const HOME_AND_OFFICE: &str = r#"
        listen-host = "127.0.0.1"

        [[clients]]
        name = "home"
        psk-files = ["home.psk"]
        ports = 443

        [[clients]]
        name = "office"
        psk-files = ["office.psk"]
        ports = 80
    "#;

    /// Writes the configuration with the clients `home` and `office`, and their PSK files.
    fn home_and_office() -> ConfigFiles {
        let files = ConfigFiles::new();
        files.psk("home", "home-psk-0123456789");
        files.psk("office", "office-psk-0123456789");
        files.write(HOME_AND_OFFICE);
        files
    }

    fn names(app_data: &ServerAppData) -> Vec<String> {
        let settings = app_data.settings();
        settings
            .clients
            .names()
            .map(|name| name.as_str().to_string())
            .collect()
    }

    #[test]
    fn test_reload_applies_the_clients_and_limits() -> Result<()> {
        let files = home_and_office();
        let mut server = start(&files, &[])?;
        assert_eq!(names(&server.app_data), ["home", "office"]);

        // The second PSK of home, office removed, lab added, and other limits.
        files.psk("home-next", "home-next-psk-0123456789");
        files.psk("lab", "lab-psk-0123456789");
        files.write(
            r#"
            listen-host = "127.0.0.1"
            max-quic-connections = 10
            max-connections-per-ip = 3

            [[clients]]
            name = "home"
            psk-files = ["home.psk", "home-next.psk"]
            ports = 443

            [[clients]]
            name = "lab"
            psk-files = ["lab.psk"]
            ports = "8000-8100"
            "#,
        );
        // E.g. lab tried to connect before.
        let lab_host = "192.0.2.7".parse().unwrap();
        for _ in 0..5 {
            server.admission.record_failure(lab_host);
        }
        assert!(server.admission.blocked_for(lab_host).is_some());
        let (logs, _logs) = collect_logs("info");
        server.reloader.reload()?;

        assert!(server.admission.blocked_for(lab_host).is_none());
        assert_eq!(names(&server.app_data), ["home", "lab"]);
        let settings = server.app_data.settings();
        let home = settings.clients.get(&"home".parse().unwrap()).unwrap();
        assert_eq!(home.psks.len(), 2);
        assert_eq!(settings.forwarding_limits.max_connections_per_ip, 3);
        assert_eq!(server.connection_limit.get(), Some(10));
        let logs = logs.lines();
        for message in [
            r#"Changed the PSKs of client "home""#,
            r#"Added client "lab""#,
            r#"Removed client "office""#,
            "at most 512 connections, 3 per address",
            "At most 10 QUIC connections from now on",
            "Lifted the blocks of addresses after failed attempts: 1",
            "Reloaded the configuration",
        ] {
            assert!(
                logs.iter().any(|line| line.contains(message)),
                "{}: {:#?}",
                message,
                logs
            );
        }
        // Nothing needs a restart.
        assert!(
            !logs.iter().any(|line| line.contains("WARN")),
            "{:#?}",
            logs
        );

        // Reloading the same configuration changes nothing.
        let (logs, _logs) = collect_logs("info");
        server.reloader.reload()?;
        assert_eq!(logs.lines().len(), 1, "{:#?}", logs.lines());
        Ok(())
    }

    #[test]
    fn test_invalid_configurations_change_nothing() -> Result<()> {
        let files = home_and_office();
        let mut server = start(&files, &[])?;
        let before = server.app_data.settings();

        for (config, error) in [
            // A PSK file that doesn't exist, while the other clients are fine.
            (
                HOME_AND_OFFICE.replace("office.psk", "missing.psk"),
                "failed to read PSK file",
            ),
            (
                HOME_AND_OFFICE.replace("[[clients]]", "[[client]]"),
                "client",
            ),
            ("listen-host = ".to_string(), "server.toml"),
            (
                HOME_AND_OFFICE.replace("name = \"office\"", "name = \"home\""),
                "client \"home\" is listed twice",
            ),
        ] {
            files.write(&config);
            let err = format!("{:#}", server.reloader.reload().unwrap_err());
            assert!(err.contains(error), "{}", err);
            assert!(Arc::ptr_eq(&server.app_data.settings(), &before));
        }
        Ok(())
    }

    #[test]
    fn test_settings_that_need_a_restart_are_named() -> Result<()> {
        let files = home_and_office();
        let mut server = start(&files, &[])?;

        files.write(&format!(
            r#"
            config-dir = "elsewhere"
            quic-listen-host = "::1"
            quic-listen-port = 4434
            quic-cert-hostname = "tunnel.example.com"
            congestion-control = "bbr"
            print-metrics = true
            provide-metrics = true
            shutdown-timeout = 1
            log-format = "json"
            log-level = "debug"
            {}
            "#,
            HOME_AND_OFFICE.replace("127.0.0.1", "0.0.0.0")
        ));
        let (logs, _logs) = collect_logs("warn");
        server.reloader.reload()?;

        // Without logging set up, as in tests, the log level stays, too.
        let logs = logs.lines();
        assert_eq!(logs.len(), 2, "{:#?}", logs);
        assert!(
            logs[0].contains("Not changing the log level: "),
            "{:#?}",
            logs
        );
        let ignored = "Not applying the changes of config-dir, listen-host, quic-listen-host, quic-listen-port, quic-cert-hostname, congestion-control, print-metrics, provide-metrics and metrics-listen, shutdown-timeout, log-format, they take effect when the server restarts";
        assert!(logs[1].contains(ignored), "{}", logs[1]);
        Ok(())
    }

    #[test]
    fn test_only_a_configuration_that_runs_the_server_is_read() {
        let matches = Args::command()
            .try_get_matches_from(["portredirect_server", "--print-quic-cert-fingerprint"])
            .unwrap();
        let err = read_config(&matches).unwrap_err();
        assert_eq!(err.to_string(), "the configuration doesn't run the server");
    }

    #[test]
    fn test_command_line_settings_stay() -> Result<()> {
        let files = home_and_office();
        let mut server = start(&files, &["--max-quic-connections", "5"])?;
        assert_eq!(server.connection_limit.get(), Some(5));

        // The command line takes precedence over the file, also when it is read again.
        files.write(&format!("max-quic-connections = 10\n{}", HOME_AND_OFFICE));
        server.reloader.reload()?;
        assert_eq!(server.connection_limit.get(), Some(5));
        Ok(())
    }
}
