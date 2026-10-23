#!/usr/bin/env bash
# Prepares a release: sets the version in Cargo.toml, updates Cargo.lock and fuzz/Cargo.lock,
# and turns the section [Unreleased] of CHANGELOG.md into one for the version, with today's date.
# See Releasing in the README.
#
# Usage: utils/set-version.sh 1.0.0

set -euo pipefail

version="${1:-}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
    echo "Usage: $0 <version>, e.g. 1.0.0 or 1.0.0-rc.3" >&2
    exit 2
fi
cd "$(dirname "$0")/.."

if grep -q "^## \[$version\]" CHANGELOG.md; then
    echo "CHANGELOG.md already has a section for $version" >&2
    exit 1
fi
if ! grep -q '^## \[Unreleased\]$' CHANGELOG.md; then
    echo "CHANGELOG.md has no section [Unreleased]" >&2
    exit 1
fi

# Only the package's own version, the first line starting with "version =".
sed -i "0,/^version = \".*\"/s//version = \"$version\"/" Cargo.toml
cargo update --workspace --quiet
cargo update --workspace --quiet --manifest-path fuzz/Cargo.toml

today="$(date -u +%Y-%m-%d)"
sed -i "s/^## \[Unreleased\]$/## [Unreleased]\n\n## [$version] - $today/" CHANGELOG.md

echo "Version $version. Describe the version at the start of its changelog section, then commit."
