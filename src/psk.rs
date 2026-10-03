// PortRedirect - Pre-shared key (PSK) command-line options shared by server and client
//
// License: GPL-3.0-only

use anyhow::{bail, Context, Result};
use clap::parser::ValueSource;
use clap::{ArgMatches, Args};
use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::private_files::warn_if_accessible_by_others;

/// Environment variable that can hold the pre-shared key.
pub const PSK_ENV_VAR: &str = "PORTREDIRECT_QUIC_PSK";

/// PSKs shorter than this are accepted, but a warning recommends a longer one.
pub const RECOMMENDED_MIN_PSK_LENGTH: usize = 16;

/// Command-line options providing the pre-shared key for authentication over QUIC.
///
/// Exactly one source is required: the PSK file, the environment variable or the
/// command-line argument.
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct PskArgs {
    /// Pre-shared key for authentication over QUIC.
    /// Command-line arguments are visible to other local users, prefer --quic-psk-file or the
    /// environment variable.
    #[arg(long, env = PSK_ENV_VAR, hide_env_values = true)]
    pub quic_psk: Option<SecretString>,

    /// File containing the pre-shared key for authentication over QUIC.
    /// Trailing line breaks are ignored.
    #[arg(long, value_name = "PATH")]
    pub quic_psk_file: Option<PathBuf>,
}

impl PskArgs {
    /// Returns the pre-shared key from whichever source was given.
    pub fn load(&self) -> Result<SecretString> {
        let psk = match (&self.quic_psk, &self.quic_psk_file) {
            (Some(psk), _) => psk.clone(),
            (None, Some(path)) => read_psk_file(path)?,
            (None, None) => bail!(
                "a pre-shared key is required: use --quic-psk-file, {} or --quic-psk",
                PSK_ENV_VAR
            ),
        };

        if psk.expose_secret().is_empty() {
            bail!("the pre-shared key must not be empty");
        }
        if psk.expose_secret().len() < RECOMMENDED_MIN_PSK_LENGTH {
            warn!(
                "The pre-shared key is shorter than {} bytes and might be guessed, use a long random key, e.g. from: openssl rand -hex 32",
                RECOMMENDED_MIN_PSK_LENGTH
            );
        }
        Ok(psk)
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

/// Logs a warning if the PSK was passed as command-line argument, where it is visible to other
/// local users in the process list.
pub fn warn_if_psk_on_command_line(matches: &ArgMatches) {
    if matches.value_source("quic_psk") == Some(ValueSource::CommandLine) {
        warn!(
            "--quic-psk is visible to other local users via the process list, use --quic-psk-file or {} instead",
            PSK_ENV_VAR
        );
    }
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

    fn parse(args: &[&str]) -> Result<(PskArgs, ArgMatches), clap::Error> {
        let matches = TestCli::command().try_get_matches_from(args)?;
        let cli = TestCli::from_arg_matches(&matches)?;
        Ok((cli.psk, matches))
    }

    fn psk_file(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), contents).unwrap();
        file
    }

    #[test]
    fn test_psk_from_command_line() {
        let (psk, matches) = parse(&["test", "--quic-psk", "secret"]).unwrap();
        assert_eq!(psk.load().unwrap().expose_secret(), "secret");
        assert_eq!(
            matches.value_source("quic_psk"),
            Some(ValueSource::CommandLine)
        );
    }

    #[test]
    fn test_psk_from_file_ignores_trailing_line_breaks() {
        for contents in ["secret", "secret\n", "secret\r\n", "secret\n\n"] {
            let file = psk_file(contents);
            let path = file.path().to_str().unwrap();
            let (psk, _) = parse(&["test", "--quic-psk-file", path]).unwrap();
            assert_eq!(psk.load().unwrap().expose_secret(), "secret");
        }
    }

    #[test]
    fn test_psk_file_keeps_inner_whitespace() {
        let file = psk_file(" sec ret \n");
        let (psk, _) = parse(&["test", "--quic-psk-file", file.path().to_str().unwrap()]).unwrap();
        assert_eq!(psk.load().unwrap().expose_secret(), " sec ret ");
    }

    #[test]
    fn test_psk_is_required() {
        let err = parse(&["test"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn test_psk_sources_are_exclusive() {
        let file = psk_file("secret");
        let path = file.path().to_str().unwrap();
        let err = parse(&["test", "--quic-psk", "secret", "--quic-psk-file", path]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn test_empty_psk_is_rejected() {
        let file = psk_file("\n");
        let (psk, _) = parse(&["test", "--quic-psk-file", file.path().to_str().unwrap()]).unwrap();
        assert!(psk.load().is_err());

        let (psk, _) = parse(&["test", "--quic-psk", ""]).unwrap();
        assert!(psk.load().is_err());
    }

    #[test]
    fn test_missing_psk_file_is_an_error() {
        let (psk, _) = parse(&["test", "--quic-psk-file", "/nonexistent/psk"]).unwrap();
        let err = psk.load().unwrap_err();
        assert!(err.to_string().contains("failed to read PSK file"));
    }
}
