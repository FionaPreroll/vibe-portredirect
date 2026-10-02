#!/bin/bash
# generate-deps.sh: Generate Cargo dependency graphs for the server, client, and library.
#
# This script will run:
#   cargo modules dependencies --bin portredirect_server > docs/cargo-mods-server.dot
#   cargo modules dependencies --bin portredirect_client > docs/cargo-mods-client.dot
#   cargo modules dependencies --lib > docs/cargo-mods-lib.dot
#
# Usage: ./docs-generate-cargo-modules-tree.sh

set -e # Exit on any error

# Ensure docs directory exists
DOCS_DIR="docs"
if [ ! -d "$DOCS_DIR" ]; then
    echo "Make sure to run this script in the repository's main directory, where ${DOCS_DIR} is located."
    exit 1
fi

if false; then
    #XXX disabled useless graphs
    # Note these graphs for the two binaries are currently kinda useless.
    FLAGS="--no-fns --no-sysroot --no-traits"

    # Generate dependency graph for the server binary
    echo "Generating dependency graph for portredirect_server binary..."
    cargo modules dependencies --bin portredirect_server $FLAGS >"$DOCS_DIR/cargo-mods-server.dot"
    echo "Saved to $DOCS_DIR/cargo-mods-server.dot"

    # Generate dependency graph for the client binary
    echo "Generating dependency graph for portredirect_client binary..."
    cargo modules dependencies --bin portredirect_client $FLAGS >"$DOCS_DIR/cargo-mods-client.dot"
    echo "Saved to $DOCS_DIR/cargo-mods-client.dot"
fi

FLAGS="--no-externs --no-fns --no-sysroot --no-traits --no-types --no-uses"

# Generate dependency graph for the library
echo "Generating dependency graph for the library..."
cargo modules dependencies --lib $FLAGS >"$DOCS_DIR/cargo-mods-lib.dot"
echo "Saved to $DOCS_DIR/cargo-mods-lib.dot"

echo "All dependency graphs have been generated successfully."
