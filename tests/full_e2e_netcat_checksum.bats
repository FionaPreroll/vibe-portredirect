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
    sleep 5
}

teardown() {
    get_metrics "$LOG_DIR/portredirect_client_metrics.log"

    # Kill background processes
    kill $SERVER_PID $CLIENT_PID || true
}

send_and_verify() {
    #local size=$1
    local filename="testfile_10GB"

    # Fetch huge test file, probably faster than our RNG with urandom
    [ -e "$filename" ] || wget -qO "$filename" https://hil-speed.hetzner.com/10GB.bin

    # Slice off file of specified size
    #head -c ${size}M <10GB.bin >$filename

    # Compute original MD5 hash
    local original_md5=$(md5sum "$filename" | awk '{print $1}')

    # Start netcat listener on port 5201 (bridged by portredirect)
    nc -l -p 2222 >received_$filename &
    sleep 1 # Allow listener to start

    # Send the file via netcat to port 1111, which is redirected to 2222
    time cat "$filename" | pv -rta | nc -N 127.0.0.1 1111

    # Compute received file MD5 hash
    local received_md5=$(md5sum "received_$filename" | awk '{print $1}')

    pkill -f "nc -l -p 2222" || true

    # Compare hashes
    [ "$original_md5" = "$received_md5" ]
}

@test "Netcat + MD5 data integrity test" {
    send_and_verify
}
