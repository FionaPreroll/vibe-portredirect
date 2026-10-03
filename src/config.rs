// PortRedirect - Configuration files
//
// Both programs can read their settings from a TOML file given with --config-file. Its keys are
// the names of the command-line options without the leading dashes, e.g. `max-connections`, and
// its values are written like on the command line. A setting on the command line, or in the
// environment, takes precedence over the file, and the file over the defaults. Secrets are only
// referenced by the paths of the files holding them. Relative paths in the file are relative to
// the file's directory, so the configuration doesn't depend on the working directory, e.g. of a
// service.
//
// License: GPL-3.0-only

use anyhow::{anyhow, bail, Context, Result};
use clap::parser::ValueSource;
use clap::ArgMatches;
use serde::de::{self, DeserializeOwned, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::ffi::OsStr;
use std::fmt::{self, Display};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::psk::PSK_ENV_VAR;
use crate::server::PortSpec;

/// The environment variable that held the PSK before 1.0, see [`check_renamed_environment`].
pub const RENAMED_PSK_ENV_VAR: &str = "PORTREDIRECT_QUIC_PSK";

/// Fails if the command-line `args` use an option by the name it had before 1.0, with a message
/// naming the new one. Clap would only guess a similar option, often the wrong one. `renamed`
/// holds pairs of old and new names.
pub fn check_renamed_options<I>(args: I, renamed: &[(&str, &str)]) -> Result<()>
where
    I: IntoIterator,
    I::Item: AsRef<OsStr>,
{
    for arg in args {
        let arg = arg.as_ref().to_string_lossy();
        let option = arg.split_once('=').map_or(&*arg, |(option, _)| option);
        if let Some((old, new)) = renamed.iter().find(|(old, _)| *old == option) {
            bail!("{} was renamed to {}", old, new);
        }
    }
    Ok(())
}

/// Fails if the environment has the variable that held the PSK before 1.0, which would be
/// ignored otherwise.
pub fn check_renamed_environment() -> Result<()> {
    if std::env::var_os(RENAMED_PSK_ENV_VAR).is_some() {
        bail!(
            "the environment variable {} was renamed to {}",
            RENAMED_PSK_ENV_VAR,
            PSK_ENV_VAR
        );
    }
    Ok(())
}

/// Reads the configuration file at `path`.
///
/// Fails on unknown keys, so typos don't go unnoticed, and on invalid values.
pub fn read_config_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read the configuration file {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("invalid configuration file {}", path.display()))
}

/// Returns whether the option with the clap ID `id` was given on the command line or in the
/// environment, so it takes precedence over the configuration file.
pub fn given(matches: &ArgMatches, id: &str) -> bool {
    matches!(
        matches.value_source(id),
        Some(ValueSource::CommandLine | ValueSource::EnvVariable)
    )
}

/// Returns the setting of an option with a default value: `cli` if the option was given on the
/// command line or in the environment, otherwise `file` if the configuration file has it,
/// otherwise `cli`, which then is the default.
pub fn merge<T>(matches: &ArgMatches, id: &str, cli: T, file: Option<T>) -> T {
    match file {
        Some(file) if !given(matches, id) => file,
        _ => cli,
    }
}

/// Returns the setting of an option without default value, see [`merge`].
pub fn merge_option<T>(
    matches: &ArgMatches,
    id: &str,
    cli: Option<T>,
    file: Option<T>,
) -> Option<T> {
    if given(matches, id) {
        cli
    } else {
        file.or(cli)
    }
}

/// Returns the setting of the required option `--{option}`, or an error if neither the command
/// line nor the configuration file has it.
pub fn required<T>(setting: Option<T>, option: &str) -> Result<T> {
    setting.ok_or_else(|| {
        anyhow!(
            "--{0} is required, on the command line or as {0} in the configuration file",
            option
        )
    })
}

/// Returns `path` from the configuration file at `config_file`, relative to the file's directory
/// if it is relative.
pub fn resolve_path(config_file: &Path, path: &Path) -> PathBuf {
    match config_file.parent() {
        Some(directory) if path.is_relative() => directory.join(path),
        _ => path.to_path_buf(),
    }
}

/// Deserializes a value from a string with its `FromStr` implementation, e.g. a log level, so
/// the configuration file accepts the same values as the command line.
pub fn parsed<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    String::deserialize(deserializer)?
        .parse()
        .map_err(de::Error::custom)
}

/// Deserializes an optional value, see [`parsed`]. Needs `#[serde(default)]`.
pub fn optional_parsed<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    parsed(deserializer).map(Some)
}

/// Deserializes ports: a string like on the command line, e.g. `"80,443,8000-8100"`, a port
/// number, or an array of port numbers and such strings, e.g. `[80, 443, "8000-8100"]`.
pub fn ports<'de, D>(deserializer: D) -> Result<Vec<PortSpec>, D::Error>
where
    D: Deserializer<'de>,
{
    let Ports(ports) = Ports::deserialize(deserializer)?;
    if ports.is_empty() {
        return Err(de::Error::custom("no ports given"));
    }
    Ok(ports)
}

/// Deserializes optional ports, see [`ports`]. Needs `#[serde(default)]`.
pub fn optional_ports<'de, D>(deserializer: D) -> Result<Option<Vec<PortSpec>>, D::Error>
where
    D: Deserializer<'de>,
{
    ports(deserializer).map(Some)
}

/// Ports in the configuration file, see [`ports`].
struct Ports(Vec<PortSpec>);

impl<'de> Deserialize<'de> for Ports {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(PortsVisitor)
    }
}

struct PortsVisitor;

impl<'de> Visitor<'de> for PortsVisitor {
    type Value = Ports;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(r#"ports like "80,443,8000-8100" or [80, 443, "8000-8100"]"#)
    }

    fn visit_str<E: de::Error>(self, ports: &str) -> Result<Ports, E> {
        ports
            .split(',')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map(Ports)
            .map_err(E::custom)
    }

    fn visit_i64<E: de::Error>(self, port: i64) -> Result<Ports, E> {
        match u16::try_from(port) {
            // Checked like on the command line, e.g. port 0.
            Ok(port) => self.visit_str(&port.to_string()),
            Err(_) => Err(E::custom(format!("Invalid port: {}", port))),
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Ports, A::Error> {
        let mut ports = Vec::new();
        while let Some(Ports(more)) = items.next_element()? {
            ports.extend(more);
        }
        Ok(Ports(ports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::AllowedPorts;
    use clap::{Arg, ArgAction, Command};
    use tracing::level_filters::LevelFilter;

    fn command() -> Command {
        Command::new("test")
            .arg(Arg::new("port").long("port").default_value("80"))
            .arg(Arg::new("host").long("host"))
            .arg(Arg::new("flag").long("flag").action(ArgAction::SetTrue))
    }

    #[test]
    fn test_command_line_overrides_file_overrides_default() {
        let matches = command().get_matches_from(["test", "--host", "cli", "--port", "80"]);
        // Given on the command line, even with the default value.
        assert_eq!(
            merge_option(&matches, "host", Some("cli"), Some("file")),
            Some("cli")
        );
        assert_eq!(merge(&matches, "port", 80, Some(8080)), 80);
        // Not given.
        let matches = command().get_matches_from(["test"]);
        assert_eq!(merge(&matches, "port", 80, Some(8080)), 8080);
        assert_eq!(merge(&matches, "port", 80, None), 80);
        assert_eq!(
            merge_option(&matches, "host", None, Some("file")),
            Some("file")
        );
        assert_eq!(merge_option::<&str>(&matches, "host", None, None), None);
        assert!(merge(&matches, "flag", false, Some(true)));
    }

    #[test]
    fn test_renamed_options_are_named_with_their_new_names() {
        let renamed = [("--quic-psk", "--psk"), ("--local-host", "--listen-host")];
        let current = [
            "--psk",
            "secret",
            "--listen-host",
            "::",
            "--psk=--local-host",
        ];
        assert!(check_renamed_options(current, &renamed).is_ok());
        for args in [
            &["--quic-psk", "secret"][..],
            &["--quic-psk=secret"],
            &["--psk", "secret", "--local-host", "::"],
        ] {
            let err = check_renamed_options(args, &renamed).unwrap_err();
            let renamed_to = [
                "--quic-psk was renamed to --psk",
                "--local-host was renamed to --listen-host",
            ];
            assert!(
                renamed_to.contains(&err.to_string().as_str()),
                "{:?}: {}",
                args,
                err
            );
        }
    }

    #[test]
    fn test_required_settings() {
        assert_eq!(required(Some(5), "max-connections").unwrap(), 5);
        let err = required::<u16>(None, "listen-host").unwrap_err();
        assert_eq!(
            err.to_string(),
            "--listen-host is required, on the command line or as listen-host in the configuration file"
        );
    }

    #[test]
    fn test_relative_paths_are_relative_to_the_file() {
        let file = Path::new("/etc/portredirect/server.toml");
        assert_eq!(
            resolve_path(file, Path::new("clients/home.psk")),
            Path::new("/etc/portredirect/clients/home.psk")
        );
        assert_eq!(
            resolve_path(file, Path::new("/var/lib/psk")),
            Path::new("/var/lib/psk")
        );
        assert_eq!(
            resolve_path(Path::new("server.toml"), Path::new("psk")),
            Path::new("psk")
        );
        assert_eq!(
            resolve_path(Path::new("/"), Path::new("psk")),
            Path::new("psk")
        );
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    struct TestFile {
        #[serde(default, deserialize_with = "optional_parsed")]
        log_level: Option<LevelFilter>,
        #[serde(default, deserialize_with = "optional_ports")]
        allowed_client_ports: Option<Vec<PortSpec>>,
        max_connections: Option<std::num::NonZeroU32>,
    }

    fn read(text: &str) -> Result<TestFile> {
        let file = tempfile::NamedTempFile::new()?;
        std::fs::write(file.path(), text)?;
        read_config_file(file.path())
    }

    fn read_ports(ports: &str) -> Result<Vec<PortSpec>> {
        read(&format!("allowed-client-ports = {}", ports))?
            .allowed_client_ports
            .context("no ports")
    }

    #[test]
    fn test_values_are_parsed_like_on_the_command_line() -> Result<()> {
        let file = read("log-level = \"debug\"\nmax-connections = 5\n")?;
        assert_eq!(file.log_level, Some(LevelFilter::DEBUG));
        assert_eq!(file.max_connections.map(|n| n.get()), Some(5));
        let file = read("")?;
        assert!(file.log_level.is_none() && file.allowed_client_ports.is_none());
        Ok(())
    }

    #[test]
    fn test_ports_as_text_numbers_or_arrays() -> Result<()> {
        for (ports, allowed, denied) in [
            (
                r#""80, 8000-8100""#,
                &[80, 8000, 8050, 8100][..],
                &[81, 443][..],
            ),
            ("443", &[443], &[80]),
            (
                r#"[80, "443,8443", "8000-8100"]"#,
                &[80, 443, 8443, 8050],
                &[81],
            ),
            (r#"["1-65535"]"#, &[1, 65535], &[0]),
        ] {
            let specs = read_ports(ports)?;
            for &port in allowed {
                assert!(specs.allows(port), "{} should allow {}", ports, port);
            }
            for &port in denied {
                assert!(!specs.allows(port), "{} should deny {}", ports, port);
            }
        }
        Ok(())
    }

    #[test]
    fn test_invalid_files_are_rejected() {
        for (text, expected) in [
            ("max-conections = 5", "unknown field `max-conections`"),
            ("max-connections = 0", "nonzero"),
            ("max-connections = \"5\"", "invalid type"),
            ("log-level = \"loud\"", "error parsing level filter"),
            ("log-level = 3", "invalid type"),
            ("log-level = ", "invalid configuration file"),
            ("allowed-client-ports = \"0-100\"", "random port"),
            ("allowed-client-ports = 0", "random port"),
            ("allowed-client-ports = 70000", "Invalid port: 70000"),
            ("allowed-client-ports = -1", "Invalid port: -1"),
            ("allowed-client-ports = [80, \"x\"]", "Invalid port"),
            ("allowed-client-ports = \"\"", "Invalid port"),
            ("allowed-client-ports = []", "no ports given"),
            ("allowed-client-ports = true", "ports like"),
        ] {
            let err = read(text).unwrap_err();
            let message = format!("{:#}", err);
            assert!(message.contains(expected), "{:?}: {}", text, message);
            assert!(
                message.contains("invalid configuration file"),
                "{:?}: {}",
                text,
                message
            );
        }
    }

    #[test]
    fn test_missing_file_is_an_error() {
        let err =
            read_config_file::<TestFile>(Path::new("/nonexistent/portredirect.toml")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "failed to read the configuration file /nonexistent/portredirect.toml"
        );
    }
}
