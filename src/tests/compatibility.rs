// PortRedirect - The compatibility promise of 1.x
//
// From 1.0 on, the command line, the environment variables, the configuration files and the
// metric names stay compatible in all 1.x versions (see CHANGELOG.md). These tests compare them
// with what 1.0 has, kept in src/tests/compatibility/: everything of 1.0 must still be there,
// new options and metrics may be added. A renamed option or metric fails here, even if the
// README was changed along with it.
//
// To add something new to the promise, add its line to v1.txt.
//
// License: GPL-3.0-only

use clap::{Command, CommandFactory};
use std::collections::BTreeSet;
use std::path::Path;

use crate::client;
use crate::server;

/// The options, environment variables and metrics of 1.0, one per line.
const V1: &str = include_str!("compatibility/v1.txt");

/// Returns the lines of the interface the programs have now, in the format of v1.txt.
fn current_interface() -> BTreeSet<String> {
    let mut lines = BTreeSet::new();
    for (program, command) in [
        ("server", server::config::Args::command()),
        ("client", client::config::Args::command()),
    ] {
        add_command_line(&mut lines, program, &command);
    }

    server::metrics::METRICS.client(&"compatibility-test".parse().unwrap());
    for (program, registry) in [
        ("server", &server::metrics::METRICS.registry),
        ("client", &client::metrics::METRICS.registry),
    ] {
        for family in registry.gather() {
            let mut labels: Vec<&str> = family
                .get_metric()
                .first()
                .map(|metric| metric.get_label().iter().map(|l| l.name()).collect())
                .unwrap_or_default();
            labels.sort_unstable();
            let labels = if labels.is_empty() {
                String::new()
            } else {
                format!("{{{}}}", labels.join(","))
            };
            lines.insert(format!("{} metric {}{}", program, family.name(), labels));
        }
    }
    lines
}

/// Adds the options of `command` and their environment variables to `lines`.
fn add_command_line(lines: &mut BTreeSet<String>, program: &str, command: &Command) {
    for arg in command.get_arguments() {
        if let Some(long) = arg.get_long() {
            lines.insert(format!("{} option --{}", program, long));
        }
        if let Some(env) = arg.get_env() {
            lines.insert(format!("{} env {}", program, env.to_string_lossy()));
        }
    }
}

#[test]
fn test_the_interface_of_1_0_is_still_there() {
    let current = current_interface();
    let missing: Vec<&str> = V1
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| !current.contains(*line))
        .collect();
    assert!(
        missing.is_empty(),
        "1.x promises to keep these, but they are gone or changed:\n{}\n\nThe programs have now:\n{}",
        missing.join("\n"),
        current.into_iter().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn test_configuration_files_of_1_0_are_still_valid() -> anyhow::Result<()> {
    // Every setting of 1.0, as in the examples of 1.0 with all settings active. Unknown keys
    // are errors, so a renamed or removed setting fails here.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests/compatibility");
    server::config::ConfigFile::read(&dir.join("server-v1.toml"))?;
    client::config::ConfigFile::read(&dir.join("client-v1.toml"))?;
    Ok(())
}
