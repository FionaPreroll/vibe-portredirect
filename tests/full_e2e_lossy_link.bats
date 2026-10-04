#!/usr/bin/env bats
# Sends data through a tunnel whose QUIC packets cross an emulated link with 50 ms round-trip
# time and 1 % loss in each direction (examples/link_emulator.rs), and checks that it arrives
# unchanged, in both directions.
#
#   nc  -->  portredirect_server  -->  link_emulator  -->  portredirect_client  -->  nc
#            (127.0.0.1:1112)          (QUIC, 4444 to 4443)                     (127.0.0.1:2223)

load tools.bats

setup() {
    check_command nc
    check_command cmp

    LOG_NAME="prrs_full_e2e_lossy_link"

    # Create log files base dir
    mkdir -p ./testlogs
    LOG_DIR=$(mktemp -p ./testlogs -d "${LOG_NAME}_$(date +%Y%m%d-%H%M%S).XXXXXX")

    # Build the project, when not running in CI
    [ -e .ci ] || cargo build --release --bins --example link_emulator
}

teardown() {
    stop_processes $SERVER_PID $CLIENT_PID $NC_PID
    # SIGINT makes the emulator print how many datagrams it forwarded and dropped.
    kill -INT $EMULATOR_PID 2>/dev/null || true
    wait $EMULATOR_PID 2>/dev/null || true
}

# Starts server, link emulator and client, with the congestion controller $1 on both sides.
start_tunnel() {
    ./target/release/portredirect_server \
        --listen-host 127.0.0.1 --allowed-client-ports 1112 \
        --quic-listen-host 127.0.0.1 --quic-listen-port 4443 --psk ilovespezifisch \
        --congestion-control "$1" \
        >"$LOG_DIR/portredirect_server.log" 2>&1 &
    SERVER_PID=$!

    ./target/release/examples/link_emulator \
        --listen 127.0.0.1:4444 --upstream 127.0.0.1:4443 --rtt-ms 50 --loss-percent 1 \
        >"$LOG_DIR/link_emulator.log" 2>&1 &
    EMULATOR_PID=$!

    # Wait a short time for the server to be ready
    sleep 1

    ./target/release/portredirect_client \
        --destination-host 127.0.0.1 --destination-port 2223 --remote-listen-port 1112 \
        --quic-remote-host 127.0.0.1 --quic-remote-port 4444 --psk ilovespezifisch \
        --congestion-control "$1" \
        >"$LOG_DIR/portredirect_client.log" 2>&1 &
    CLIENT_PID=$!

    # The server listens on the port once the tunnel is set up.
    wait_for_listener 1112
}

# Sends $1 bytes of random data to the destination and back, and compares them.
send_both_ways() {
    head -c "$1" /dev/urandom >"$LOG_DIR/sent"

    # To the destination
    nc -l -p 2223 >"$LOG_DIR/received" &
    NC_PID=$!
    wait_for_listener 2223
    nc -N 127.0.0.1 1112 <"$LOG_DIR/sent"
    wait $NC_PID
    cmp "$LOG_DIR/sent" "$LOG_DIR/received"

    # From the destination
    nc -l -p 2223 -N <"$LOG_DIR/sent" &
    NC_PID=$!
    wait_for_listener 2223
    nc 127.0.0.1 1112 </dev/null >"$LOG_DIR/received_back"
    wait $NC_PID
    cmp "$LOG_DIR/sent" "$LOG_DIR/received_back"
}

@test "Data crosses a link with delay and loss unchanged (CUBIC)" {
    start_tunnel cubic
    # CUBIC takes each loss for congestion, so the tunnel is slow on this link.
    send_both_ways 2M
}

@test "Data crosses a link with delay and loss unchanged (BBR)" {
    start_tunnel bbr
    send_both_ways 20M
}
