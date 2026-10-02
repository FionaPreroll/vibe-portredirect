#!/usr/bin/env bats
# This is a benchmark test that shows the performance of a direct connection and a tunneled connection for comparison.
# It ensures that all commands run successfully and that there are no transmission errors.
#
# Here are diagrams of the two connection setups:
#          Baseline Test
#  ------------------------------------------------------
# |                                                      |
# |   iperf3 Client              iperf3 Server           |
# |   (connect to port 5201)  -->  (listening on 5201)   |
# |                                                      |
#  ------------------------------------------------------
#          Tunneled Test
#  --------------------------------------------------------------
# |                                                              |
# |   iperf3 Client                                              |
# |   (connects to port 10001)                                   |
# |          |                                                   |
# |          v                                                   |
# |   portredirect_server                                        |
# |   (127.0.0.1:10001)                                          |
# |          |                                                   |
# |          |  Establishes a QUIC tunnel using port 4433        |
# |          v                                                   |
# |   portredirect_client                                        |
# |   (connects via QUIC to server on port 4433)                 |
# |          |                                                   |
# |          v                                                   |
# |   iperf3 Server                                              |
# |   (listening on port 5201)                                   |
# |                                                              |
#  --------------------------------------------------------------

load tools.bats

setup() {
    LOG_NAME="prrs_full_e2e_benchmark"

    # Create log files base dir
    mkdir -p ./testlogs
    LOG_DIR=$(mktemp -p ./testlogs -d "${LOG_NAME}_$(date +%Y%m%d-%H%M%S).XXXXXX")

    # Build the project, when not running in CI
    [ -e .ci ] || cargo build --release

    # Start portredirect server in background
    ./target/release/portredirect_server \
        --local-host 127.0.0.1 --local-port 10001 \
        --quic-server-host 127.0.0.1 --quic-server-port 4433 --quic-psk ilovespezifisch \
        --print-metrics \
        >"$LOG_DIR/portredirect_server.log" 2>&1 &
    SERVER_PID=$!

    # Wait a short time for the server to be ready
    sleep 1

    # Start portredirect client in background
    ./target/release/portredirect_client \
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
    get_metrics "$LOG_DIR/portredirect_client_metrics.log"

    kill $SERVER_PID $CLIENT_PID $IPERF_PID || true
}

@test "Baseline iperf3 test (direct connection)" {
    run bash -c "iperf3 -J -c 127.0.0.1 -p 5201 | tee \"$LOG_DIR/iperf3_baseline_client.json\""
    [ "$status" -eq 0 ]
    run bash -c "iperf3 -J -c 127.0.0.1 -p 5201 -R | tee \"$LOG_DIR/iperf3_baseline_client_R.json\""
    [ "$status" -eq 0 ]
}

@test "Tunneled iperf3 test (via portredirect)" {
    run bash -c "iperf3 -J -c 127.0.0.1 -p 10001 | tee \"$LOG_DIR/iperf3_tunneled_client.json\""
    [ "$status" -eq 0 ]
    run bash -c "iperf3 -J -c 127.0.0.1 -p 10001 -R | tee \"$LOG_DIR/iperf3_tunneled_client_R.json\""
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

@test "Tunneled iperf3 test varying parallel connections (10 to 10000)" {
    # Define a list of parallel connection counts.
    # Adjust or expand the list as needed to gather the desired data points.
    for p in 5 10 20 50; do
        echo "Running test with $p parallel connections"
        # Forward test
        run bash -c "iperf3 -J -c 127.0.0.1 -p 10001 -P $p | tee \"$LOG_DIR/iperf3_tunneled_client_parallel_${p}.json\""
        [ "$status" -eq 0 ]
        # Reverse test
        run bash -c "iperf3 -J -c 127.0.0.1 -p 10001 -P $p -R | tee \"$LOG_DIR/iperf3_tunneled_client_parallel_R_${p}.json\""
        [ "$status" -eq 0 ]

        # Check that no ERROR occurred in the portredirect logs for this iteration
        if grep -q "ERROR" "$LOG_DIR/portredirect_server.log"; then
            echo "ERROR found in server log for $p parallel connections"
            exit 1
        fi
        if grep -q "ERROR" "$LOG_DIR/portredirect_client.log"; then
            echo "ERROR found in client log for $p parallel connections"
            exit 1
        fi
    done
}
