#!/usr/bin/env bats

load tools.bats

setup() {
    LOG_NAME="prrs_full_e2e_connection_stress_test"

    # Create log files base dir
    mkdir -p ./testlogs
    LOG_DIR=$(mktemp -p ./testlogs -d "${LOG_NAME}_$(date +%Y%m%d-%H%M%S).XXXXXX")

    # Build the project, when not running in CI
    [ -e .ci ] || cargo build --release

    # Start portredirect server in background
    ./target/release/portredirect_server \
        --local-host 127.0.0.1 --local-port 1111 \
        --quic-server-host 127.0.0.1 --quic-server-port 4433 --quic-psk ilovespezifisch \
        --print-metrics \
        >"$LOG_DIR/portredirect_server.log" 2>&1 &
    SERVER_PID=$!

    # Wait a short time for the server to be ready
    sleep 1

    # Start portredirect client in background
    ./target/release/portredirect_client \
        --destination-host 127.0.0.1 --destination-port 2222 \
        --quic-remote-host 127.0.0.1 --quic-remote-port 4433 \
        --quic-remote-hostname-match localhost --quic-psk ilovespezifisch \
        --provide-metrics \
        >"$LOG_DIR/portredirect_client.log" 2>&1 &
    CLIENT_PID=$!

    # Wait for services to start up
    sleep 1
}

teardown() {
    get_metrics "$LOG_DIR/portredirect_client_metrics.log"
    kill $SERVER_PID $CLIENT_PID
}

pr_log_error_check() {
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

# Helper function to run the connection stress test.
# Arguments:
#   $1: mode ("baseline" for direct connections, "benchmark" for tunneled tests)
#   $2: number of workers
#   $3: total bytes to transfer (e.g. "$((1 * 1024 ** 3))")
#   $4: a suffix for the log file name (e.g., "1c_1gb")
run_stress_test() {
    local mode="$1"
    local workers="$2"
    local total_bytes="$3"
    local suffix="$4"

    local server_port listener_port
    if [ "$mode" = "baseline" ]; then
        server_port=1234
        listener_port=1234
    else
        server_port=1111
        listener_port=2222
    fi

    local log_file="$LOG_DIR/cst_${mode}_${suffix}.log"
    run python3 ./utils/connection_stress_test.py --server-port "$server_port" --listener-port "$listener_port" \
        --log-file "$log_file" \
        --workers "$workers" \
        --total-bytes "$total_bytes"
    [ "$status" -eq 0 ]

    if [ "$mode" = "benchmark" ]; then
        run pr_log_error_check
        [ "$status" -eq 0 ]
    fi
}

@test "Baseline test (direct connection)" {
    run_stress_test baseline 1 "$((1 * 1024 ** 3))" "1c_1gb"
    run_stress_test baseline 10 "$((100 * 1024 ** 2))" "10c_100mb"
    run_stress_test baseline 50 "$((20 * 1024 ** 2))" "50c_20mb"
    run_stress_test baseline 100 "$((10 * 1024 ** 2))" "100c_10mb"
}

@test "Tunneled test (1 single connection, 1 GiB)" {
    run_stress_test benchmark 1 "$((1 * 1024 ** 3))" "1c_1gb"
}

@test "Tunneled test (10 connections, 100 MiB)" {
    run_stress_test benchmark 10 "$((100 * 1024 ** 2))" "10c_100mb"
}

@test "Tunneled test (50 connections, 20 MiB)" {
    run_stress_test benchmark 50 "$((20 * 1024 ** 2))" "50c_20mb"
}

@test "Tunneled test (100 connections, 10 MiB)" {
    run_stress_test benchmark 100 "$((10 * 1024 ** 2))" "100c_10mb"
}
