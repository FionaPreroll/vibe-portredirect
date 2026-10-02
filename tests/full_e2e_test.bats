#!/usr/bin/env bats
# This test checks that portredirect runs and doesn't blatantly crash or exits with an error.

load tools.bats

setup() {
    LOG_NAME="prrs_full_e2e_test"

    # Create log files base dir
    mkdir -p ./testlogs
    LOG_DIR=$(mktemp -p ./testlogs -d "${LOG_NAME}_$(date +%Y%m%d-%H%M%S).XXXXXX")

    # Build the project, when not running in CI
    [ -e .ci ] || cargo build --release

    # Start portredirect server in background
    RUST_BACKTRACE=1 RUST_LOG=tracing=debug ./target/release/portredirect_server \
        --local-host 127.0.0.1 --local-port 10001 \
        --quic-server-host 127.0.0.1 --quic-server-port 4433 --quic-psk ilovespezifisch \
        --print-metrics \
        >"$LOG_DIR/portredirect_server.log" 2>&1 &
    SERVER_PID=$!

    # Wait a short time for the server to be ready
    sleep 1

    # Start portredirect client in background
    RUST_BACKTRACE=1 RUST_LOG=tracing=debug ./target/release/portredirect_client \
        --destination-host 127.0.0.1 --destination-port 5201 \
        --quic-remote-host 127.0.0.1 --quic-remote-port 4433 \
        --quic-remote-hostname-match localhost --quic-psk ilovespezifisch \
        --provide-metrics \
        >"$LOG_DIR/portredirect_client.log" 2>&1 &
    CLIENT_PID=$!

    # Start iperf3 server in background
    iperf3 -s \
        >"$LOG_DIR/iperf_server.log" 2>&1 &
    IPERF_PID=$!

    # Wait for services to start up
    sleep 5
}

teardown() {
    kill $SERVER_PID $CLIENT_PID $IPERF_PID || true
}

@test "Tunneled iperf3 test (via portredirect)" {
    # forward test
    run iperf3 -c 127.0.0.1 -p 10001 -l 5
    [ "$status" -eq 0 ]

    # reverse test
    run iperf3 -c 127.0.0.1 -p 10001 -l 5 -R
    [ "$status" -eq 0 ]

    # get metrics, ensure this test fails if metrics don't work
    run get_metrics "$LOG_DIR/portredirect_client_metrics.log"
    [ "$status" -eq 0 ]

    # Check that no ERROR occurred in the portredirect logs
    if grep -q "ERROR" "$LOG_DIR/portredirect_server.log"; then
        echo "ERROR found in server log"
        exit 1
    fi
    if grep -q "ERROR" "$LOG_DIR/portredirect_client.log"; then
        echo "ERROR found in client log"
        exit 1
    fi
}
