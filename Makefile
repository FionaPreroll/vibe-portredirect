#############################################
# Makefile for Cargo and Python Project
#
# Targets:
#   all           : Run tests and build release binaries (default target).
#   docs          : Generate documentation by analyzing Cargo modules and rendering GraphViz graphs.
#   build         : Build the Cargo project in debug mode.
#   release       : Build the Cargo project in release mode and list the resulting binaries.
#   lint          : Run Rust linter (cargo clippy) and check Python formatting (black) on utils and tests.
#   lint_fix      : Automatically apply Rust suggestions and format Python files.
#   test          : Run all tests: Cargo tests, Python unit tests, and BATS tests.
#   test_cargo    : Run Cargo tests.
#   test_python   : Run Python unit tests (Data Cruncher and Connection Stress Test).
#   test_bats     : Run BATS tests.
#   clean         : Clean build artifacts using Cargo's built-in clean command.
#   run_server    : Run the 'portredirect_server' binary with extra arguments. Pass args via the ARGS variable.
#   run_client    : Run the 'portredirect_client' binary with extra arguments. Pass args via the ARGS variable.
#
# Usage Examples:
#   make
#       Runs all tests and builds release binaries (default).
#
#   make build
#       Builds the project in debug mode.
#
#   make release
#       Builds the project in release mode.
#
#   make lint
#       Runs lint checks on Rust and Python code.
#
#   make lint_fix
#       Automatically fixes lint issues for Rust and Python code.
#
#   make test
#       Runs all tests (Cargo, Python, and BATS).
#
#   make clean
#       Cleans build artifacts.
#
#   make run_server ARGS="--arg1 value1 --arg2 value2"
#       Runs the server binary with additional arguments.
#
#   make run_client ARGS="--argA valueA"
#       Runs the client binary with additional arguments.
#############################################

.PHONY: all docs build release lint test test_cargo test_python clean run_server run_client

# Default target: build for release.
all: test release

# ------------------------------
# Documentation targets.
# ------------------------------
# * (This target is called by CI as well.)
docs:
	@echo "Analyzing Cargo module..."
	@./utils/docs-generate-cargo-modules-tree.sh
	@echo "Render GraphViz graphs for Docs."
	@./utils/render-diagrams.sh ./docs/*.dot

# ------------------------------
# Build targets.
# ------------------------------
# Build the Cargo project (debug mode).
# * (This target is called by CI as well.)
build:
	@echo "Building Cargo project (debug mode)..."
	@cargo build $(ARGS)

# Build the Cargo project in release mode.
release:
	@echo "Building Cargo project (release mode)..."
	@cargo build --release $(ARGS)
	@ls -lh target/release

# ------------------------------
# Lint targets.
# ------------------------------
# Run Rust linter and Python code formatter checks.
# * (This target is called by CI as well.)
lint:
	@echo "Running Rust linter (cargo clippy)..."
	@cargo clippy --all-targets --all-features -- -D warnings
	@echo "Running Python code formatter check (black) on utils and tests..."
	@if command -v black >/dev/null 2>&1; then \
		black --check utils/*.py; \
	else \
		echo "Black is not installed. Skipping Python formatting check."; \
	fi

# Automatically fix lint issues.
lint_fix:
	@echo "Running cargo fix to automatically apply Rust suggestions..."
	@cargo fix --allow-dirty --allow-staged
	@echo "Running black to auto-format Python files in utils and tests..."
	@if command -v black >/dev/null 2>&1; then \
		black utils/*.py; \
	else \
		echo "Black is not installed. Skipping Python formatting fix."; \
	fi
	
# ------------------------------
# Test targets.
# ------------------------------
# Top-level test target: runs both Cargo and Python tests.
test: test_cargo test_python

# Run BATS tests.
test_bats:
	@echo "Running BATS tests..."
	@bats tests/ $(ARGS)

# Run Cargo tests.
# * (This target is called by CI as well.)
test_cargo:
	@echo "Running Cargo tests..."
	@cargo test $(ARGS)

# Run Cargo tests with Backtrace enabled.
test_cargo_debug:
	@echo "Running Cargo tests..."
	@RUST_BACKTRACE=full RUST_LOG=tracing=debug cargo test $(ARGS)

# Run Python unit tests.
# * (This target is called by CI as well.)
test_python:
	@echo "Running Python unit tests (Data Cruncher)..."
	@cd utils && python -m unittest test_cst_datacruncher.py
	@echo "Running Python unit tests (Connection Stress Test)..."
	@cd utils && python -m unittest test_connection_stress_test.py

# ------------------------------
# Clean target.
# ------------------------------
# Clean build artifacts using Cargo's built-in clean command.
clean:
	@echo "Cleaning build artifacts..."
	@cargo clean

# ------------------------------
# Run targets.
# ------------------------------
# Run the portredirect_server binary. Pass extra arguments via ARGS.
run_server:
	@echo "Running portredirect_server, local port 1234 ..."
	@cargo run --bin portredirect_server -- --quic-cert-hostname 127.0.0.1 --local-host 127.0.0.1 --local-port 1234 --quic-psk foo $(ARGS)

# Run the portredirect_client binary. Pass extra arguments via ARGS.
run_client:
	@echo "Running portredirect_client, destination port 2222 ..."
	@cargo run --bin portredirect_client -- --destination-host 127.0.0.1 --destination-port 2222 --quic-remote-host 127.0.0.1 --quic-remote-port 4433 --quic-psk foo $(ARGS)
