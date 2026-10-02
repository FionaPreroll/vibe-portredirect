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
