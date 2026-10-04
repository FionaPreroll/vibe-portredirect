check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "$1 not found. Please install it."
        exit 1
    fi
}

get_metrics() {
    # Get metrics from portredirect client
    # Uses -i to include the HTTP response headers in the output,
    # so we have at least some output when the metrics are empty.
    curl -i http://localhost:9898/metrics -o "${1:-metrics.log}"
}

stop_processes() {
    # Stop background processes and wait until they have exited, so the next test can use their
    # ports again: portredirect shuts down gracefully on SIGTERM, which takes a moment.
    # Processes that are still running after 10 seconds are killed, and the test fails.
    kill "$@" 2>/dev/null || true
    for _ in $(seq 100); do
        if ! kill -0 "$@" 2>/dev/null; then
            wait "$@" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
    echo "Processes $* still running 10 seconds after SIGTERM, killing them"
    kill -KILL "$@" 2>/dev/null || true
    wait "$@" 2>/dev/null || true
    return 1
}

require_ipv6() {
    # Skips the test on a machine without IPv6, i.e. without the loopback address ::1, unless
    # PORTREDIRECT_TEST_IPV6 is "required", as in CI: then the test fails.
    if grep -qs '^00000000000000000000000000000001 ' /proc/net/if_inet6; then
        return 0
    fi
    if [ "${PORTREDIRECT_TEST_IPV6:-}" = required ]; then
        echo "PORTREDIRECT_TEST_IPV6 requires IPv6, but there is no ::1"
        return 1
    fi
    skip "no IPv6 on this machine"
}

wait_for_listener() {
    # Wait until a process listens on TCP port $1, at most 10 seconds. Unlike a test connection,
    # this doesn't use up a listener that accepts a single connection, like nc -l.
    local port
    port=$(printf '%04X' "$1")
    for _ in $(seq 100); do
        # The second column is the local address, the fourth the state: 0A means LISTEN.
        if cat /proc/net/tcp /proc/net/tcp6 2>/dev/null |
            awk -v port=":$port" '$2 ~ port "$" && $4 == "0A" { found = 1 } END { exit !found }'; then
            return 0
        fi
        sleep 0.1
    done
    echo "Nothing listens on TCP port $1 after 10 seconds"
    return 1
}
