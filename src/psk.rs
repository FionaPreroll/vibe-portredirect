// PortRedirect - Pre-shared key (PSK) command-line options shared by server and client
//
// License: GPL-3.0-only

use anyhow::{bail, Context, Result};
use clap::parser::ValueSource;
use clap::{ArgMatches, Args};
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::private_files::warn_if_accessible_by_others;

/// Environment variable that can hold the pre-shared key.
pub const PSK_ENV_VAR: &str = "PORTREDIRECT_PSK";

/// PSKs shorter than this are accepted, but a warning recommends a longer one.
pub const RECOMMENDED_MIN_PSK_LENGTH: usize = 16;

/// Command-line options providing the pre-shared key for authentication over QUIC.
///
/// At most one source can be given: the PSK file, the environment variable or the command-line
/// argument. Without any, the configuration file has to name a PSK file.
#[derive(Args, Debug)]
#[group(multiple = false)]
pub struct PskArgs {
    /// Pre-shared key for authentication over QUIC.
    /// Command-line arguments are visible to other local users, prefer --psk-file or the
    /// environment variable.
    #[arg(long, env = PSK_ENV_VAR, hide_env_values = true)]
    pub psk: Option<SecretString>,

    /// File containing the pre-shared key for authentication over QUIC.
    /// Trailing line breaks are ignored. A pre-shared key is required: from this file, the
    /// environment variable, --psk or the configuration file.
    #[arg(long, value_name = "PATH")]
    pub psk_file: Option<PathBuf>,
}

impl PskArgs {
    /// Returns the source of the pre-shared key given on the command line or in the
    /// environment, if any. `matches` are the command line's matches, which tell the two apart.
    pub fn source(&self, matches: &ArgMatches) -> Option<PskSource> {
        match (&self.psk, &self.psk_file) {
            (Some(psk), _) if matches.value_source("psk") == Some(ValueSource::CommandLine) => {
                Some(PskSource::CommandLine(psk.clone()))
            }
            (Some(psk), _) => Some(PskSource::Environment(psk.clone())),
            (None, Some(path)) => Some(PskSource::File(path.clone())),
            (None, None) => None,
        }
    }
}

/// Where a pre-shared key comes from.
#[derive(Clone, Debug)]
pub enum PskSource {
    /// The command-line argument, which other local users can see in the process list.
    CommandLine(SecretString),
    /// The environment variable [`PSK_ENV_VAR`].
    Environment(SecretString),
    /// A file, named on the command line or in the configuration file.
    File(PathBuf),
}

impl PskSource {
    /// Returns the pre-shared key.
    ///
    /// Fails if it is empty or its file can't be read. Logs a warning if other local users can
    /// see it, or if it is short.
    pub fn load(&self) -> Result<SecretString> {
        let psk = match self {
            Self::CommandLine(psk) => {
                warn!(
                    "--psk is visible to other local users via the process list, use --psk-file or {} instead",
                    PSK_ENV_VAR
                );
                psk.clone()
            }
            Self::Environment(psk) => psk.clone(),
            Self::File(path) => read_psk_file(path)?,
        };

        if psk.expose_secret().is_empty() {
            bail!("the pre-shared key from {} is empty", self);
        }
        if psk.expose_secret().len() < RECOMMENDED_MIN_PSK_LENGTH {
            warn!(
                "The pre-shared key from {} is shorter than {} bytes and might be guessed, use a long random key, e.g. from: openssl rand -hex 32",
                self, RECOMMENDED_MIN_PSK_LENGTH
            );
        }
        Ok(psk)
    }
}

impl fmt::Display for PskSource {
    /// Names the source, never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandLine(_) => f.write_str("--psk"),
            Self::Environment(_) => f.write_str(PSK_ENV_VAR),
            Self::File(path) => write!(f, "{}", path.display()),
        }
    }
}

/// Reads a pre-shared key from a file, ignoring trailing line breaks.
pub fn read_psk_file(path: &Path) -> Result<SecretString> {
    warn_if_accessible_by_others(path);

    let mut psk = fs::read_to_string(path)
        .with_context(|| format!("failed to read PSK file {}", path.display()))?;
    let len = psk.trim_end_matches(['\r', '\n']).len();
    psk.truncate(len);

    // Move the String into the secret, so it is zeroized on drop.
    Ok(SecretString::from(psk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{error::ErrorKind, CommandFactory, FromArgMatches, Parser};

    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(flatten)]
        psk: PskArgs,
    }

    /// Returns the PSK source the command line `args` give.
    fn parse(args: &[&str]) -> Result<Option<PskSource>, clap::Error> {
        let matches = TestCli::command().try_get_matches_from(args)?;
        let cli = TestCli::from_arg_matches(&matches)?;
        Ok(cli.psk.source(&matches))
    }

    /// Returns the PSK the command line `args` give.
    fn load(args: &[&str]) -> Result<SecretString> {
        parse(args)?.context("no PSK given")?.load()
    }

    fn psk_file(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), contents).unwrap();
        file
    }

    #[test]
    fn test_psk_from_command_line() {
        let source = parse(&["test", "--psk", "secret"]).unwrap().unwrap();
        assert!(matches!(source, PskSource::CommandLine(_)), "{:?}", source);
        assert_eq!(source.load().unwrap().expose_secret(), "secret");
    }

    #[test]
    fn test_psk_from_file_ignores_trailing_line_breaks() {
        for contents in ["secret", "secret\n", "secret\r\n", "secret\n\n"] {
            let file = psk_file(contents);
            let path = file.path().to_str().unwrap();
            let source = parse(&["test", "--psk-file", path]).unwrap().unwrap();
            assert!(matches!(&source, PskSource::File(file) if file == Path::new(path)));
            assert_eq!(source.load().unwrap().expose_secret(), "secret");
        }
    }

    #[test]
    fn test_psk_file_keeps_inner_whitespace() {
        let file = psk_file(" sec ret \n");
        let psk = load(&["test", "--psk-file", file.path().to_str().unwrap()]).unwrap();
        assert_eq!(psk.expose_secret(), " sec ret ");
    }

    #[test]
    fn test_psk_is_optional_on_the_command_line() {
        // The configuration file may name the PSK file instead.
        assert!(parse(&["test"]).unwrap().is_none());
    }

    #[test]
    fn test_psk_sources_are_exclusive() {
        let file = psk_file("secret");
        let path = file.path().to_str().unwrap();
        let err = parse(&["test", "--psk", "secret", "--psk-file", path]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn test_empty_psk_is_rejected() {
        let file = psk_file("\n");
        let path = file.path().to_str().unwrap();
        let err = load(&["test", "--psk-file", path]).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("the pre-shared key from {} is empty", path)
        );

        let err = load(&["test", "--psk", ""]).unwrap_err();
        assert_eq!(err.to_string(), "the pre-shared key from --psk is empty");
    }

    #[test]
    fn test_sources_are_named_without_the_psk() {
        let sources = [
            PskSource::CommandLine("secret".into()),
            PskSource::Environment("secret".into()),
            PskSource::File("/etc/portredirect/psk".into()),
        ];
        let names: Vec<String> = sources.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["--psk", PSK_ENV_VAR, "/etc/portredirect/psk"]);
        for source in &sources {
            assert!(!format!("{:?}", source).contains("secret"), "{:?}", source);
        }
        assert_eq!(sources[1].load().unwrap().expose_secret(), "secret");
    }

    #[test]
    fn test_missing_psk_file_is_an_error() {
        let err = load(&["test", "--psk-file", "/nonexistent/psk"]).unwrap_err();
        assert!(err.to_string().contains("failed to read PSK file"));
    }
}
