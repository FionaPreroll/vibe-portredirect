#!/usr/bin/env bash
# Runs the examples in docker/example on this host, the server and the client's stack, and
# checks that nginx answers through the tunnel. Uses the images by the names in the examples,
# so tag the images to test like that, e.g. after building them from the release archives, see
# build-context.sh. Needs Docker Compose, and the ports 80/tcp and 4433/udp.
#
# Usage: docker/test-example.sh
set -euo pipefail

examples=$(cd "$(dirname "$0")/example" && pwd)
server=(docker compose --project-directory "$examples/server" --project-name portredirect-test-server)
client=(docker compose --project-directory "$examples/client" --project-name portredirect-test-client)

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        "${server[@]}" logs || true
        "${client[@]}" logs || true
    fi
    "${client[@]}" down --volumes || true
    "${server[@]}" down --volumes || true
    exit "$status"
}
trap cleanup EXIT

# Waits until the logs of the compose project, the command after the text, contain the text.
wait_for_log() {
    local text=$1
    shift
    for _ in $(seq 60); do
        if "$@" logs 2>&1 | grep -q "$text"; then
            return 0
        fi
        sleep 1
    done
    echo "No \"$text\" in the logs" >&2
    return 1
}

# The examples take their settings from .env, or from these variables, which take precedence.
PORTREDIRECT_PSK=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
export PORTREDIRECT_PSK
"${server[@]}" up --detach
wait_for_log "Certificate fingerprint" "${server[@]}"
PORTREDIRECT_QUIC_CERT_FINGERPRINT=$("${server[@]}" logs | grep -o 'sha256:[0-9a-f]*' | head -n 1)
# The host's address, at which the client's container reaches the server's published port.
PORTREDIRECT_QUIC_REMOTE_HOST=$(hostname -I | cut -d ' ' -f 1)
export PORTREDIRECT_QUIC_CERT_FINGERPRINT PORTREDIRECT_QUIC_REMOTE_HOST

"${client[@]}" up --detach
wait_for_log "Tunnel established" "${client[@]}"
curl --silent --show-error --fail --retry 10 --retry-delay 1 --retry-all-errors \
    http://127.0.0.1/ | grep "Welcome to nginx"

# The server keeps its certificate and private key in its volume, owned by its user.
"${server[@]}" exec portredirect-server ls -ln /etc/portredirect
echo "The examples work."
