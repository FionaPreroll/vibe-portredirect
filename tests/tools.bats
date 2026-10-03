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
