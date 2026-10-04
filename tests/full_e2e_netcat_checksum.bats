#!/usr/bin/env bats

load tools.bats

ensure_deps() {
    check_command cargo
    check_command nc
    check_command md5sum
    check_command pv
}

setup() {
    ensure_deps

    LOG_NAME="prrs_full_e2e_netcat_checksum"

    # Create log files base dir
    mkdir -p ./testlogs
    LOG_DIR=$(mktemp -p ./testlogs -d "${LOG_NAME}_$(date +%Y%m%d-%H%M%S).XXXXXX")

    # Build the project, when not running in CI
    [ -e .ci ] || cargo build --release
}

# Starts the server and the client with everything on the loopback address $1: the tunnel, the
# external connection and the destination. The client gets $2 as the server's address, and
# trusts the server's certificate, which is issued for 127.0.0.1, by that name.
start_tunnel() {
    local host=$1 remote_host=$2

    # Start portredirect server in background
    ./target/release/portredirect_server \
        --listen-host "$host" --allowed-client-ports 1111 \
        --quic-listen-host "$host" --quic-listen-port 4433 --psk ilovespezifisch \
        --print-metrics \
        >"$LOG_DIR/portredirect_server.log" 2>&1 &
    SERVER_PID=$!

    # Wait a short time for the server to be ready
    sleep 1

    # Start portredirect client in background
    ./target/release/portredirect_client \
        --destination-host "$host" --destination-port 2222 --remote-listen-port 1111 \
        --quic-remote-host "$remote_host" --quic-remote-port 4433 \
        --quic-cert-hostname 127.0.0.1 \
        --psk ilovespezifisch \
        --provide-metrics \
        >"$LOG_DIR/portredirect_client.log" 2>&1 &
    CLIENT_PID=$!

    # Wait for services to start up
    sleep 5
}

teardown() {
    # Nothing to stop after a skipped test.
    [ -n "${SERVER_PID:-}" ] || return 0

    get_metrics "$LOG_DIR/portredirect_client_metrics.log"

    # Stop background processes, including the netcat listener if the test failed
    stop_processes $SERVER_PID $CLIENT_PID $NC_PID
}

# Sends $2 bytes of random data, e.g. 1G, through the tunnel started on the loopback address $1,
# and compares checksums.
send_and_verify() {
    local host=$1 size=$2
    local filename="testfile_$size"

    # Generate random test data locally, instead of depending on an external download
    [ -e "$filename" ] || head -c "$size" /dev/urandom >"$filename"

    # Compute original MD5 hash
    local original_md5=$(md5sum "$filename" | awk '{print $1}')

    # Start netcat listener on port 2222 (bridged by portredirect)
    nc -l "$host" 2222 >received_$filename &
    NC_PID=$!
    wait_for_listener 2222

    # Send the file via netcat to port 1111, which is redirected to 2222
    time cat "$filename" | pv -rta | nc -N "$host" 1111

    # Compute received file MD5 hash
    local received_md5=$(md5sum "received_$filename" | awk '{print $1}')

    kill $NC_PID 2>/dev/null || true

    # Compare hashes
    [ "$original_md5" = "$received_md5" ]
}

@test "Netcat + MD5 data integrity test" {
    start_tunnel 127.0.0.1 127.0.0.1
    send_and_verify 127.0.0.1 1G
}

@test "Netcat + MD5 data integrity test over IPv6" {
    require_ipv6
    # The client gets the address in brackets, as in URLs.
    start_tunnel ::1 "[::1]"
    send_and_verify ::1 256M
}
