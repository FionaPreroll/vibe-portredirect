# PortRedirect

*Glue your frontend to the backend!*

![PortRedirect Logo showing a green pipe with the text superimposed with golden color](./docs/portredirect_logo.png)

## Introduction

PortRedirect is a lightweight user-space TCP forwarder that bridges your frontend and backend via a secure QUIC tunnel. It has two components:

- **Server:** Listens for incoming TCP connections (e.g., on port 443) and tunnels them over a persistent QUIC connection.
- **Client:** Connects to the QUIC server, receives tunneled streams, and forwards them to the target TCP service (e.g., `localhost:4433`).

Both use a pre-shared key (PSK) for authentication. The server auto-generates a self-signed certificate and private key on first run (stored in `~/.config/portredirect`). The client verifies the server by the certificate's fingerprint or a copy of the certificate, see [Server Certificate](#server-certificate).

### **Bling:**

[![codecov](https://codecov.io/gh/FionaPreroll/vibe-portredirect/graph/badge.svg)](https://codecov.io/gh/FionaPreroll/vibe-portredirect)

### Concept

In this example, we compare two methods for a web browser to reach a secure HTTPS server:

- **Baseline (Direct) Connection:**  
  The user's web browser establishes a direct TCP connection to a public web server hosting HTTPS (Figure 1).

- **Tunneled Connection via PortRedirect:**
  In this scenario, a home server running PortRedirect's client establishes a secure QUIC tunnel with the small cheap public server, which then forwards incoming connections to us. The connections get patched through to a local HTTPS server (see Figure 2).
  The public side running PortRedirect's server can then accept TCP connections from browsers. By forwarding them through the established QUIC tunnel, they can communicate with the HTTPS server, almost as if we had rented a big publicly reachable server.

> **Note:** The arrows in the following diagrams indicate the initiator of the connection (not necessarily the direction of data flow, which can always be bidirectional).

#### Figure 1: Direct TCP Connection

![Direct Connection Diagram](docs/benchmark_baseline_test.svg)

*In this scenario, the user's web browser connects directly to the public HTTPS server using a standard TCP connection.*

#### Figure 2: Tunneled Connection via PortRedirect

![Tunneled Connection Diagram](docs/benchmark_tunneled_test.svg)

*In the tunneled scenario, the user's web browser still initiates a TCP connection to the public endpoint. However, the connection is then forwarded through a secure QUIC tunnel, established between the home server (portredirect_client) and the frontend server (portredirect_server), to reach the internal HTTPS server.*

## Installation

### Prebuilt Binaries

Each [release](https://github.com/FionaPreroll/vibe-portredirect/releases), e.g. `v1.0.0-rc.1`, has binaries for Linux on x86_64 (`amd64`), 64-bit ARM (`arm64`) and 32-bit ARM (`armv7`, e.g. a Raspberry Pi 2 or newer with a 32-bit system), in two variants:

- **glibc** (default), e.g. `portredirect-linux-amd64.tar.gz`: for distributions with glibc 2.17 or newer, i.e. practically all but those with musl, like Alpine.
- **musl**, e.g. `portredirect-linux-amd64-musl.tar.gz`: linked statically, so they run on any distribution, but are a little slower where the CPU limits the throughput, see [docs/PERFORMANCE.md](docs/PERFORMANCE.md#recommendations).

The pre-release [`snapshot`](https://github.com/FionaPreroll/vibe-portredirect/releases/tag/snapshot) has the same binaries of the latest commit on `main`: for each commit on `main`, CI builds them, runs the tests for their architecture and replaces the previous ones.
Release candidates, e.g. `v1.0.0-rc.1`, are pre-releases, too, to try a version in real use before it is released.

```sh
release=v1.0.0-rc.1    # or snapshot
curl -LO https://github.com/FionaPreroll/vibe-portredirect/releases/download/$release/portredirect-linux-amd64.tar.gz
tar -xzf portredirect-linux-amd64.tar.gz
sudo install portredirect-linux-amd64/portredirect_* /usr/local/bin/
```

Each archive also has example configuration files with every setting, `examples/server.toml` and `examples/client.toml`, see [Configuration File](#configuration-file).
The release notes describe how to check a download with `SHA256SUMS` and the attestation of where it was built.

### Docker

Images of both programs with the [prebuilt binaries](#prebuilt-binaries), for amd64, arm64 and armv7:

- `ghcr.io/fionapreroll/portredirect-server` and `ghcr.io/fionapreroll/portredirect-client`
- On Debian with glibc, or with the suffix `-alpine` on Alpine with musl:
  - `latest` and `alpine`: the newest [release](#prebuilt-binaries) that isn't a pre-release. Until 1.0.0 is released, the latest commit on `main`.
  - `<version>`, e.g. `1.0.0-rc.1` and `1.0.0-rc.1-alpine`: a release, also a pre-release.
  - `edge` and `edge-alpine`: the latest commit on `main`; `sha-<commit>` and `sha-<commit>-alpine`: an earlier commit.

They run as an unprivileged user, are configured with [environment variables](#environment-variables) or a [configuration file](#configuration-file), and keep their configuration directory, e.g. the server's certificate and private key, in `/etc/portredirect`.

The client fits into a Docker Compose stack: it forwards the connections that the server accepts to another container, e.g. a web server, so the stack publishes no ports and needs no port forwarding on its router.
[docker/example](docker/example) has such a stack with nginx, and the server for it:

1. On the public host, in `docker/example/server`: copy `example.env` to `.env` and set a PSK in it, e.g. from `openssl rand -hex 32`. Run `docker compose up -d`. `docker compose logs | grep fingerprint` shows the fingerprint of the server's certificate.
2. In `docker/example/client`: copy `example.env` to `.env` and set the server's address, the fingerprint and the same PSK in it. Run `docker compose up -d`.
3. nginx answers on the server's port 80.

- **Ports:** The server's container publishes the ports clients may ask for, e.g. 80, and the QUIC port, 4433/udp. Docker passes on the external clients' IPv4 addresses, which the server's limits per address need. IPv6 clients arrive from Docker's own address unless IPv6 is enabled in Docker; then let the server listen on `::`, for IPv6 and IPv4.
- **UDP buffers:** Containers get the host's limits, so set them on the hosts, see [Performance](#performance).
- **Reloading:** With a configuration file, `docker compose kill -s HUP portredirect-server` makes the server read it again, see [Reloading the Configuration](#reloading-the-configuration). Environment variables only change when Compose creates the container again.

### From Source

Build both binaries from a checkout of this repository (requires Rust 1.88 or newer):

```sh
cargo install --locked --path .
```

`--locked` uses the dependency versions from `Cargo.lock`, which are the ones tested and audited in CI.

> **Note:** The latest `portredirect` package on crates.io, version 0.3.0, predates the current protocol version 5 (see [docs/PROTOCOL.md](docs/PROTOCOL.md)) and can't talk to this version. It will be updated once this version has proven stable in practice. Server and client must speak the same protocol version.
> [CHANGELOG.md](CHANGELOG.md) lists the changes between versions and which ones changed the protocol.

## Usage

### Running the Frontend Server

For example, if your public server (accessible on TCP port 443) should forward traffic over a VPN (with an internal IP of `10.0.0.1`) on port 12345, run:

```sh
portredirect_server \
    --listen-host 0.0.0.0 --allowed-client-ports 443 \
    --quic-listen-host 10.0.0.1 --quic-listen-port 12345 \
    --quic-cert-hostname 10.0.0.1 \
    --psk-file /etc/portredirect/psk
```

**Parameters:**

- **`--listen-host`:** Where to listen for incoming TCP connections, e.g. `0.0.0.0` for every IPv4 address, or `::` for every IPv6 and IPv4 address.
- **`--allowed-client-ports`:** TCP ports clients may ask the server to listen on, e.g. `443` or `80,443,8000-8100`.
- **`--quic-listen-host` & `--quic-listen-port`:** Where to listen for the QUIC tunnel (UDP), by default `127.0.0.1` and `4433`. `::` is every IPv6 and IPv4 address, as for `--listen-host`.
- **`--quic-cert-hostname`:** IP address or DNS name the generated certificate is issued for, the client verifies it. Only used when the certificate is generated on first start (default `127.0.0.1`).
- **`--psk-file`:** File containing the pre-shared key, see [PSK Best Practices](#psk-best-practices).
- **`--config-file`:** TOML file with settings, e.g. a list of clients, see [Configuration File](#configuration-file). `SIGHUP` makes the server read it again, see [Reloading the Configuration](#reloading-the-configuration).
- **`--config-dir`:** Where the certificate and private key are stored (default `~/.config/portredirect`). If only one of them is there, the server doesn't start, instead of generating a new pair that clients wouldn't trust.
- **`--print-quic-cert-fingerprint`:** Print the fingerprint of the certificate, for the clients' `--quic-cert-fingerprint`, and exit, see [Server Certificate](#server-certificate). If there is no certificate yet, generates it first.
- **`--provide-metrics`:** Serve Prometheus metrics at `http://127.0.0.1:9899/metrics`, or at the address given with `--metrics-listen`, see [Metrics](#metrics). The endpoint has no authentication, only make it reachable from trusted networks.
- **`--print-metrics`:** Print the metrics to stderr when they change, each summed over all clients.
- **`--shutdown-timeout`:** Seconds that running forwarded connections may take to finish when the server shuts down (default 5), see [Shutting Down](#shutting-down).
- **`--log-level`:** `off`, `error`, `warn`, `info` (default), `debug` or `trace`. Logs go to stderr. The `RUST_LOG` environment variable, if set, takes precedence and can set levels per module, e.g. `RUST_LOG=info,portredirect::forward=debug`.
- **`--log-format`:** `text` (default) or `json`: one JSON object per line, with the fields of each message, e.g. for log collectors.
- **`--congestion-control`:** How fast the server sends: `cubic` (default) or `bbr`, which is much faster on links that lose packets, e.g. wireless ones, see [Performance](#performance).

**Limits** for the resources a single host can use:

- **`--max-quic-connections`:** Maximum number of QUIC connections, including connections that are not authenticated yet (default 64). Each client uses one.
- **`--max-connections`:** Maximum number of concurrently forwarded TCP connections per client (default 512). Further connections wait until one ends.
- **`--max-connections-per-ip`:** Maximum number of concurrently forwarded TCP connections per external IP address, for IPv6 per /64 network (default 64, `0` for no limit). Further connections are closed right away. Raise it if many users share an address, e.g. behind a NAT.
- **`--max-connection-rate-per-ip`** and **`--max-connection-burst-per-ip`:** How fast an external IP address, for IPv6 a /64 network, may open new forwarded TCP connections: after up to `--max-connection-burst-per-ip` at once (default 64), at most `--max-connection-rate-per-ip` per second (default 20, `0` for no limit). Further connections are closed right away. Each forwarded connection makes the client connect to the destination, so this limits the load a single host can put on it. Raise them like `--max-connections-per-ip`.
- **`--idle-timeout`:** Close forwarded TCP connections after this many seconds without data transfer (default 600, `0` to never close idle connections). Raise it for protocols with long idle times, e.g. SSH without keep-alive messages.

The server also limits the QUIC connections per address, gives clients 10 seconds for the TLS handshake and blocks addresses for 10 minutes after repeated failed attempts, see [Limits](docs/PROTOCOL.md#limits).

### Running the Backend Client

To forward traffic to a local service (e.g., an `nginx` server on `127.0.0.1:4433`), run:

```sh
portredirect_client \
    --destination-host 127.0.0.1 --destination-port 4433 \
    --remote-listen-port 443 \
    --quic-remote-host 10.0.0.1 --quic-remote-port 12345 \
    --quic-cert-fingerprint sha256:<fingerprint of the server's certificate> \
    --psk-file /etc/portredirect/psk
```

**Parameters:**

- **`--destination-host` & `--destination-port`:** The target TCP service. A name is looked up for each forwarded connection, and each of its addresses is tried, so the client follows changes, e.g. of a container that was created again.
- **`--remote-listen-port`:** The TCP port the server should listen on for you. Must be one of the server's `--allowed-client-ports`.
- **`--quic-remote-host` & `--quic-remote-port`:** The QUIC server’s address. A name is looked up for each connection attempt, e.g. for a server with a dynamic address. If it has IPv4 and IPv6 addresses, the client connects to an IPv4 address, see `--quic-local-host`.
- **`--quic-local-host` & `--quic-local-port`** (optional): Address and UDP port to send to the server from. By default any address, of IPv6 and IPv4, or only of IPv4 on a system without IPv6, and any port. With an IPv6 address such as `::`, the client prefers the server's IPv6 addresses; with an IPv4 address such as `0.0.0.0`, it only connects over IPv4.
- **`--quic-cert-fingerprint`** (recommended): Trust the server's certificate by its fingerprint instead of a copy of `cert.der`, see [Server Certificate](#server-certificate). Give it several times to trust several certificates, e.g. while the server's certificate changes.
- **`--quic-cert-hostname`** (optional): Name the server's certificate must be issued for, if it differs from `--quic-remote-host`. Must match the server's `--quic-cert-hostname`. Not checked with `--quic-cert-fingerprint`.
- **`--psk-file`:** File containing the pre-shared key, must match the server’s PSK.
- **`--client-name`** (optional): Name the client authenticates with, 1 to 64 letters, digits, dots, underscores or hyphens (default `default`). A server configured with `--psk-file` and `--allowed-client-ports` knows a single client named `default`, see [Several Clients and Standby](#several-clients-and-standby).
- **`--config-file`:** TOML file with settings, see [Configuration File](#configuration-file).
- **`--config-dir`:** Where the server's certificate `cert.der` is read from, unless `--quic-cert-fingerprint` is given (default `~/.config/portredirect`).
- **`--max-connections`:** Maximum number of concurrently forwarded connections (default 512).
- **`--provide-metrics`:** Serve Prometheus metrics at `http://127.0.0.1:9898/metrics`, or at the address given with `--metrics-listen`, see [Metrics](#metrics). The endpoint has no authentication, only make it reachable from trusted networks.
- **`--shutdown-timeout`**, **`--log-level`**, **`--log-format`** and **`--congestion-control`:** As for the server. `--congestion-control` decides how fast each side sends, so set it on both.
- **`--log-connections`:** Log each forwarded connection, independently of `--log-level`: the external client's address, which the server passes on, the destination, how long the connection lasted and how much data it transferred. Off by default, as it logs the addresses of the external clients. A connection that fails is logged as `Connection aborted`, with the error.
  ```
  INFO portredirect::connections: Connection opened external_client=198.51.100.7:56360 destination=127.0.0.1:4433
  INFO portredirect::connections: Connection closed external_client=198.51.100.7:56360 destination=127.0.0.1:4433 duration_ms=1520 bytes_to_destination=517 bytes_from_destination=10342
  ```

> **Important:** The client must trust the server's certificate. Start the server first to generate it, then give the client the certificate's fingerprint with `--quic-cert-fingerprint`, see [Server Certificate](#server-certificate).
> Or copy **only the certificate** `~/.config/portredirect/cert.der` from the server to the client's configuration directory (by default the same path).
> Never copy the private key `key.der`: anyone who has it can impersonate your server. The server creates it readable only by its owner (mode `0600`) and warns if it is accessible by others.

### Configuration File

Both programs can read their settings from a [TOML](https://toml.io) file given with `--config-file`.
Its keys are the names of the options without the leading dashes, and its values are written like on the command line:

```toml
# /etc/portredirect/client.toml
destination-host = "127.0.0.1"
destination-port = 4433
remote-listen-port = 443
quic-remote-host = "10.0.0.1"
quic-remote-port = 12345
quic-cert-fingerprint = "sha256:<fingerprint of the server's certificate>"
psk-file = "psk"
log-level = "warn"
```

```sh
portredirect_client --config-file /etc/portredirect/client.toml
```

[examples/server.toml](examples/server.toml) and [examples/client.toml](examples/client.toml) have every setting, with explanations and the defaults.

- **Precedence:** Options on the command line or in the [environment](#environment-variables) take precedence over the file, and the file over the defaults. So `--log-level debug` overrides the file for a single run. On the command line, flags like `--print-metrics` can only switch a setting on.
- **No secrets:** The file only names the files that hold the PSKs; it has no key for a PSK itself.
- **Paths:** Relative paths in the file, e.g. `psk-file` or `config-dir`, are relative to the file's directory, not to the working directory.
- **Checked:** Unknown keys, e.g. typos, and invalid values are errors: the program names the line and exits with code 2.
- **Ports:** `allowed-client-ports` and the ports of clients can also be arrays, e.g. `[80, 443, "8000-8100"]`.
- **Several values:** An option that can be given several times takes an array, e.g. `quic-cert-fingerprint = ["sha256:…", "sha256:…"]`.

### Environment Variables

Each option can also be given in an environment variable: `PORTREDIRECT_` and the option's name in capitals, with underscores, e.g. `PORTREDIRECT_DESTINATION_HOST` for `--destination-host`.
This suits containers and service managers, see [Docker](#docker):

```sh
PORTREDIRECT_DESTINATION_HOST=127.0.0.1 PORTREDIRECT_DESTINATION_PORT=4433 \
PORTREDIRECT_REMOTE_LISTEN_PORT=443 \
PORTREDIRECT_QUIC_REMOTE_HOST=10.0.0.1 PORTREDIRECT_QUIC_REMOTE_PORT=12345 \
PORTREDIRECT_QUIC_CERT_FINGERPRINT=sha256:<fingerprint of the server's certificate> \
PORTREDIRECT_PSK_FILE=/etc/portredirect/psk \
portredirect_client
```

- **Precedence:** The command line takes precedence over the environment, and the environment over the [configuration file](#configuration-file).
- **Flags** take `true` or `false`, e.g. `PORTREDIRECT_PROVIDE_METRICS=true`. `false` switches off a flag that the configuration file switches on.
- **Several values** are separated by commas, e.g. `PORTREDIRECT_ALLOWED_CLIENT_PORTS=80,443,8000-8100` or `PORTREDIRECT_QUIC_CERT_FINGERPRINT=sha256:…,sha256:…`.
- **Help:** `--help` names each option's variable. Only the server's `--print-quic-cert-fingerprint` has none: it is a command, not a setting.
- **PSK:** `PORTREDIRECT_PSK` holds the PSK itself, see [PSK Best Practices](#psk-best-practices).

### Several Clients and Standby

The server's configuration file can list several clients, each with its own name, PSK and ports, instead of the single client given by `psk-file` and `allowed-client-ports`:

```toml
# /etc/portredirect/server.toml
listen-host = "0.0.0.0"
quic-listen-host = "10.0.0.1"
quic-listen-port = 12345
quic-cert-hostname = "10.0.0.1"

[[clients]]
name = "web"
psk-files = ["clients/web.psk"]
ports = "80,443"

[[clients]]
name = "web-standby"
psk-files = ["clients/web-standby.psk"]
ports = "80,443"

[[clients]]
name = "mail"
psk-files = ["clients/mail.psk", "clients/mail-next.psk"]
ports = [25, 465, 993]
```

Each client names itself with `--client-name`, or `client-name` in its configuration file, and uses the PSK of its name.
A client can only use its own ports, so it can't take over another client's port, e.g. while that client reconnects.

- **Standby:** Clients may share ports on purpose, like `web` and `web-standby` above, e.g. for a second machine that takes over when the first one fails. Whichever client connects first gets a port; the other one keeps trying to connect (see [Reconnects and Exit Codes](#reconnects-and-exit-codes)) and gets the port once it is free. The server logs which clients share which ports when it starts, so an overlap by mistake doesn't go unnoticed.
- **Adding a client:** Add it to the server's configuration file, and make the server read the file again, see [Reloading the Configuration](#reloading-the-configuration). Until then, the server doesn't know the client's name and rejects it, and repeated attempts get the client's address blocked, see [Troubleshooting](#the-server-refuses-new-connections).
- **Changing a PSK:** A client can have two PSK files while its PSK changes, like `mail` above. Add the new PSK file to the server's configuration and reload it, switch the client to the new PSK and restart the client, then remove the old file from the server's configuration and reload it again. The other tunnels go on meanwhile.
- **Logs:** The server's log messages name the client of each connection.

### Server Certificate

On its first start, the server generates a self-signed certificate and its private key, `cert.der` and `key.der` in its configuration directory.
A client trusts the server in one of two ways:

- **By fingerprint** (recommended): the SHA-256 hash of the certificate, given with `--quic-cert-fingerprint`, or `quic-cert-fingerprint` in the configuration file. It is a line of text, e.g. for a service file or configuration management, so no file needs to be copied. The client doesn't check the name the certificate is issued for, nor how long it is valid, as the fingerprint stands for exactly one certificate.
- **By a copy** of `cert.der` in the client's configuration directory. The client also checks that the certificate is issued for its `--quic-cert-hostname`, or for the address of `--quic-remote-host`.

A fingerprint is `sha256:` and 64 hex digits. Get it on the server in either of these ways, or from the server's log, which shows it when the server starts:

```sh
portredirect_server --config-file /etc/portredirect/server.toml --print-quic-cert-fingerprint
sha256sum ~/.config/portredirect/cert.der    # the same digits, without sha256:
```

The client also accepts it without `sha256:`, and with colons between the bytes, as `openssl x509 -fingerprint -sha256` prints it.

#### Changing the Server Certificate

E.g. if the private key may have been exposed, or the certificate should be issued for another name.
With fingerprints, the clients trust the new certificate before the server uses it, so they only reconnect:

1. Prepare the new certificate in another directory. This prints its fingerprint:
   ```sh
   portredirect_server --config-dir /etc/portredirect/next --quic-cert-hostname 10.0.0.1 --print-quic-cert-fingerprint
   ```
2. On every client, add the new fingerprint to the old one and restart the client:
   ```toml
   quic-cert-fingerprint = ["sha256:<old fingerprint>", "sha256:<new fingerprint>"]
   ```
3. Move `cert.der` and `key.der` from `/etc/portredirect/next` into the server's configuration directory, replacing the old ones, and restart the server. The clients reconnect and trust the new certificate.
4. Remove the old fingerprint from the clients, and delete any copies of the old private key.

Clients that trust a copy of `cert.der` need the new one at step 3, so switch them to fingerprints first.

### Reconnects and Exit Codes

The client keeps the tunnel up on its own: whenever the connection to the server ends, it connects again, after 1 second at first and up to 60 seconds after repeated failures.
It only exits:

- with code 0 on `SIGINT` or `SIGTERM`, after letting running connections finish, see [Shutting Down](#shutting-down);
- with code 1 if connecting again would fail the same way until the configuration changes, e.g. because the server rejects the PSK or the port, or the server's certificate has none of the fingerprints or doesn't match `cert.der`;
- with code 1 if another client with the same name took over the port, e.g. a second instance by mistake: otherwise, the two would take the port from each other in turns;
- with code 2 on invalid command-line arguments or an invalid configuration file.

Under a service manager, restart the client on failures only, and not right away, e.g. with systemd:

```ini
[Service]
ExecStart=/usr/local/bin/portredirect_client --config-file /etc/portredirect/client.toml
Restart=on-failure
RestartSec=60
```

When the server shuts down, its clients notice right away and connect again once it is back.

If the client connects again while the server still holds the port for its previous connection, e.g. after the client crashed, the new connection replaces the previous one right away.

### Shutting Down

On `SIGINT` or `SIGTERM`, both programs shut down gracefully, e.g. for an update:

1. They start no new forwarded connections and tell the other side with `DRAIN`. The server closes its TCP listeners and refuses new clients. A client makes the server close its TCP listener and release the port right away, so another client can take it, e.g. a [standby client](#several-clients-and-standby) or a new instance.
2. Running forwarded connections may finish, for at most `--shutdown-timeout` seconds (default 5). Idle connections, e.g. HTTP keep-alive connections, hold up the shutdown until the timeout, too.
3. Then they close the rest, and the connection between them, so the other side notices right away.

A second `SIGINT` or `SIGTERM` closes the running connections right away.
Keep the timeout shorter than the time a service manager waits before it kills the program, e.g. `TimeoutStopSec` of systemd (90 seconds by default) or the stop timeout of Docker (10 seconds by default).

### Reloading the Configuration

On `SIGHUP`, the server reads its configuration file and the PSK files again, e.g. with `systemctl reload` and `ExecReload=/bin/kill -HUP $MAINPID` in its systemd unit, or with `docker compose kill -s HUP portredirect-server`.
It applies what can change while it runs, without touching the tunnels that the change doesn't affect:

- **Clients:** added, removed and changed clients, with their PSKs and ports. A tunnel ends if its client was removed, if the PSK it authenticated with was removed, or if it may no longer use its port. Its client learns why and exits with code 1, as it would be rejected again, see [Reconnects and Exit Codes](#reconnects-and-exit-codes).
- **Limits:** `--max-quic-connections` for new QUIC connections, and the limits of forwarded connections, e.g. `--max-connections-per-ip` or `--idle-timeout`, for the tunnels set up from then on. Lower limits don't end running connections.
- **Log level,** unless `RUST_LOG` sets the levels.
- **Blocked addresses:** The server lifts the blocks of addresses after failed attempts, see [Troubleshooting](#the-server-refuses-new-connections), as the new configuration may fix their cause, e.g. a client the server didn't know yet.

The other settings, e.g. the listen addresses and the configuration directory, take effect when the server restarts; the server warns about those that changed.
So does a new certificate, see [Changing the Server Certificate](#changing-the-server-certificate).
If the new configuration is invalid, e.g. a PSK file is missing, the server logs why and goes on with the current one: nothing of the new one applies.
Options on the command line or in the environment still take precedence over the file.

The client reads its configuration only when it starts, so restart it after a change.

### Metrics

With `--provide-metrics`, both programs serve [Prometheus](https://prometheus.io) metrics at `/metrics`: the client on `127.0.0.1:9898` by default, the server on `127.0.0.1:9899`.
All metrics are listed from the start, with 0. Metrics of the server's clients have the label `client` with the client's name; they are listed for all configured clients.

| Server metric (`portredirect_server_…`)           | Type    | Labels   | Meaning                                                                                       |
| ------------------------------------------------- | ------- | -------- | --------------------------------------------------------------------------------------------- |
| `quic_connections_refused_total`                  | counter | `reason` | QUIC connections refused before the TLS handshake: `blocked`, `connection_limit`, `address_limit` or `shutting_down`. |
| `authentication_failures_total`                   | counter |          | Failed TLS handshakes and authentication attempts, which count towards blocking an address.   |
| `tunnels_total`                                   | counter | `client` | Tunnels set up: the client authenticated and the server listens for it.                      |
| `tunnels_active`                                  | gauge   | `client` | Tunnels that are up.                                                                          |
| `keepalive_failures_total`                        | counter | `client` | Tunnels closed because no keepalive message arrived in time.                                 |
| `forwarded_connections_total`                     | counter | `client` | External connections forwarded through the tunnel.                                           |
| `forwarded_connections_active`                    | gauge   | `client` | Forwarded connections that are running.                                                       |
| `forwarded_connections_refused_total`             | counter | `client`, `reason` | External connections closed right away, as their address had too many connections (`address_limit`) or opened new ones too fast (`rate_limit`). |
| `forwarded_connections_failed_total`              | counter | `client` | External connections that couldn't be forwarded, as the client accepted no stream for them.  |
| `forwarded_connections_aborted_total`             | counter | `client` | Forwarded connections that ended with an error, e.g. an abort.                               |
| `accept_errors_total`                             | counter | `client` | Failures to accept an external connection, e.g. for lack of file descriptors.                |
| `bytes_from_external_total`                       | counter | `client` | Bytes received from external connections.                                                    |
| `bytes_to_external_total`                         | counter | `client` | Bytes sent to external connections.                                                          |

| Client metric (`portredirect_client_…`)           | Type    | Meaning                                                                             |
| ------------------------------------------------- | ------- | ----------------------------------------------------------------------------------- |
| `connection_attempts_total`                       | counter | Attempts to connect to the server.                                                  |
| `tunnels_total`                                   | counter | Tunnels set up: the client connected, authenticated and the server listens for it. |
| `tunnel_up`                                       | gauge   | 1 while the tunnel is up, else 0. Alert on it.                                      |
| `keepalive_failures_total`                        | counter | Tunnels closed because the server didn't answer keepalive messages.                |
| `forwarded_connections_total`                     | counter | Connections the server forwarded through the tunnel.                               |
| `forwarded_connections_active`                    | gauge   | Forwarded connections that are running.                                             |
| `forwarded_connections_aborted_total`             | counter | Forwarded connections that ended with an error, e.g. an abort.                     |
| `destination_connect_failures_total`              | counter | Forwarded connections for which the destination couldn't be reached.              |
| `bytes_to_destination_total`                      | counter | Bytes sent to the destination.                                                      |
| `bytes_from_destination_total`                    | counter | Bytes received from the destination.                                                |

From 1.0 on, the names and labels of the metrics only change with a new major version.

### Performance

A single forwarded connection reaches about 1 Gbit/s at 50 ms round-trip time and 400 Mbit/s at 150 ms, more connections together more, as far as the CPUs allow. [docs/PERFORMANCE.md](docs/PERFORMANCE.md) has the measurements. Two settings make a difference:

- **UDP buffers:** PortRedirect asks the operating system for 4 MiB socket buffers, so datagrams that arrive in bursts aren't lost. Linux allows only 208 KiB by default, and PortRedirect logs a hint then. On fast links, allow more on both machines, and make it permanent in `/etc/sysctl.d/`:

  ```sh
  sudo sysctl -w net.core.rmem_max=4194304 net.core.wmem_max=4194304
  ```

- **Packet loss:** the default congestion controller, CUBIC, takes every lost packet for congestion, like TCP: with 1 % loss, the tunnel slows down to a few Mbit/s. On links that lose packets for other reasons, e.g. wireless or long-distance ones, use `--congestion-control bbr` on the server and the client, which kept hundreds of Mbit/s in the same conditions. quinn, the QUIC implementation, marks BBR experimental.

### PSK Best Practices

Always use a long, random pre-shared key when operating over untrusted networks. Generate it once and store it in a file that only the user running PortRedirect can read, then copy that file to the other machine via a secure channel:

```sh
(umask 077 && mkdir -p /etc/portredirect && openssl rand -hex 32 > /etc/portredirect/psk)
```

Both programs accept the PSK from one of these sources:

- **`--psk-file <PATH>`** (recommended): Reads the PSK from a file, trailing line breaks are ignored. PortRedirect warns if the file is accessible by other users. In the environment, the same is `PORTREDIRECT_PSK_FILE`, in the [configuration file](#configuration-file) `psk-file`, or `psk-files` for each of the server's [clients](#several-clients-and-standby).
- **`PORTREDIRECT_PSK`** environment variable: Useful for container or service managers that inject secrets.
- **`--psk <PSK>`**: Avoid this outside of testing. Command-line arguments are visible to every local user in the process list (`ps`, `/proc/<pid>/cmdline`) and end up in shell histories, so PortRedirect warns when it is used.

A PSK given on the command line or in the environment takes precedence over the configuration file.

## Troubleshooting

Both programs log at the `info` level by default. `--log-level debug`, or `RUST_LOG=debug`, logs more details, e.g. each connection the server refuses, and the [metrics](#metrics) count most problems, too.

### The Server Refuses New Connections

New clients, or clients that connect again, e.g. after a restart, can't connect, while tunnels that are up keep working. The client logs this, and keeps trying with growing delays:

```
WARN … Disconnected from the server: failed to connect: aborted by peer: the server refused to accept a new connection. Reconnecting in 1.1s
```

The server refuses a connection before the TLS handshake, for one of these reasons:

| Reason                                | When                                                                              | Until                                                                       | Metric label                |
| ------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------- |
| The address is blocked                | 5 failed handshakes or authentication attempts from the address within 10 minutes | 10 minutes have passed, or the server reloads its configuration or restarts | `reason="blocked"`          |
| Too many connections from the address | 8 QUIC connections from the address, including ones that aren't authenticated yet | one of them ends                                                            | `reason="address_limit"`    |
| Too many connections                  | `--max-quic-connections`, 64 by default                                           | one of them ends                                                            | `reason="connection_limit"` |
| The server shuts down                 | e.g. for an update                                                                | it is back                                                                  | `reason="shutting_down"`    |

Addresses count per IPv4 address and per IPv6 /64 network, so clients behind the same NAT share them: a single client that fails to authenticate gets the address blocked for all of them.
A client that crashed keeps its connection until the server notices, after 30 seconds without a sign of life.

These count as failed attempts:

- **A client name the server doesn't know**, e.g. of a new client that isn't in the server's configuration file yet, or that the server didn't [read again](#reloading-the-configuration) after adding the client.
- **A wrong PSK.**
- **A failed TLS handshake**, e.g. because the client doesn't trust the server's certificate, or speaks another protocol version.
- **A handshake or authentication that doesn't finish**, within 10 seconds or because the client breaks it off.

A client that the server rejects exits with code 1, see [Reconnects and Exit Codes](#reconnects-and-exit-codes). Docker, or a service manager, that restarts it makes it try again, so a wrong setting gets the address blocked within minutes.

To find the reason:

- **Server log:** The server warns about each failed attempt, and when it blocks an address:
  ```
  WARN … Incoming connection dropped: failed to authenticate PR QUIC client from 198.51.100.7:50710: authentication rejected: unknown client name "office"
  WARN … Blocking 198.51.100.7 for 600s after 5 failed handshakes or authentication attempts
  ```
  It also warns when it refuses connections, with the reason, at most once a minute for each reason; the next warning counts the refusals in between, and the `debug` level logs each one:
  ```
  WARN … Refusing connection from 198.51.100.7:59494: the address is blocked for another 9m 12s after failed handshakes or authentication attempts
  ```
- **Client log:** The rejected client only learns that its authentication failed, not whether its name or its PSK is wrong; the server's log says which:
  ```
  ERROR … connecting again would fail the same way, giving up: tunnel failed: failed to authenticate against PR QUIC server: failed to receive acceptance: connection lost: closed by peer: authentication failed (code 1)
  ```
  A client that the server refuses names the possible reasons, once until it connects again:
  ```
  WARN … The server refuses new connections: while it blocks this address after failed handshakes or authentication attempts, e.g. of a client with a name it doesn't know or a wrong PSK from the same address, while this address or the server has too many connections, or while it shuts down. Its log says which, see Troubleshooting in PortRedirect's README
  ```
- **Metrics:** `portredirect_server_quic_connections_refused_total` counts the refused connections by the reasons above, `portredirect_server_authentication_failures_total` the failed attempts.

To recover, correct the setting, e.g. add the client to the server's configuration file, and make the server read it again with `SIGHUP`, which also lifts all blocks, see [Reloading the Configuration](#reloading-the-configuration).
A restart lifts them, too, as the server keeps them only in memory. Otherwise, a block ends after 10 minutes.
[docs/PROTOCOL.md](docs/PROTOCOL.md#limits) lists all limits.

## Authentication & Certificate Verification

PortRedirect secures QUIC tunnels using auto-generated certificates and a pre-shared key (PSK). The client verifies the server’s certificate, by its fingerprint or a copy, then the client names itself, and client and server prove to each other that they know the client's PSK, with HMAC proofs bound to the TLS session.
Only after that, the server opens the TCP port the client asked for. Addresses that fail to authenticate repeatedly are blocked for a while.

- [docs/PROTOCOL.md](docs/PROTOCOL.md) describes the protocol in detail.
- [SECURITY.md](SECURITY.md) describes the security model, known limitations and how to report vulnerabilities.
- [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) is the internal security review before 1.0.

## Development

### Getting Started

To get an overview of the codebase, use [ARCHITECTURE.md](./ARCHITECTURE.md) as an entry point.

### Tests

Run the Cargo tests and the Python unit tests of the benchmark utilities:

```sh
make test
```

The Cargo tests include end-to-end tests of a complete tunnel in `src/tests/tunnel_end_to_end.rs` and tests of the two programs in `tests/cli.rs`.
Tests of IPv6 need the loopback address `::1`. On a machine without it, they skip their checks of IPv6, unless the environment variable `PORTREDIRECT_TEST_IPV6` is `required`, as in CI: then they fail. The same holds for the BATS tests.

To see which code the Cargo tests cover, install [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) and run `make coverage`.
It prints a summary per file and writes an HTML report with the covered lines to `target/llvm-cov/html`.

Before committing, run the linters (`cargo fmt --check`, `cargo clippy` and, if installed, `black`):

```sh
make lint
```

### Fuzzing and Dependency Checks

The fuzz targets in `fuzz/` feed random input to the parsers of the protocol.
They need a nightly toolchain and [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz); `make fuzz` runs each of them for a minute, see [fuzz/README.md](fuzz/README.md).
`make test` runs a short smoke test of the same parsers on stable Rust.

[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) checks the dependencies for known vulnerabilities, licenses that don't go with the GPL, and sources other than crates.io, as configured in `deny.toml`:

```sh
make deny
```

### BATS Tests

The BATS tests run the release binaries with real tools (`iperf3`, `nc`, `pv`, `curl` and the Python utilities in `utils/`).
Install [BATS-Core](https://github.com/bats-core/bats-core) and these tools, then run all of them with `make test_bats`, or a single one with:

```sh
bats tests/<test_file.bats>
```

### Releasing

1. In a pull request, set the version in `Cargo.toml`, e.g. `1.0.0-rc.1`, update `Cargo.lock` and `fuzz/Cargo.lock` with `cargo update --workspace` and `cargo update --workspace --manifest-path fuzz/Cargo.toml`, and turn the section `[Unreleased]` of [CHANGELOG.md](CHANGELOG.md) into one for the version, with the date.
2. Once it is merged, tag the merge commit with `v` and the version, and push the tag:
   ```sh
   git tag --annotate v1.0.0-rc.1 --message "PortRedirect 1.0.0-rc.1" <commit>
   git push origin v1.0.0-rc.1
   ```
3. The workflow `release.yml` builds and tests the binaries for the tag, checks that it matches the version in `Cargo.toml` and is on `main`, and publishes the release: the binaries with the version's section of the changelog as notes, and Docker images tagged with the version, and with `latest` if it is the newest release. A version with a suffix, e.g. `-rc.1`, becomes a pre-release, which `latest` doesn't point to.

If publishing fails, run the workflow again: it completes the draft of the release it left. It doesn't change a published release.

## Command-Line Help

Both programs print their version with `--version`. For a complete list of options:

- **Server Help:**  

  ```sh
  portredirect_server --help
  ```

- **Client Help:**  

  ```sh
  portredirect_client --help
  ```

- **Developer Help:**  

  ```sh
  # This means please look at the documentation inside the supplied `Makefile`
  less Makefile
  ```

## Overview & Limitations

PortRedirect is ideal for simple TCP-to-QUIC tunneling setups:

- **Protocol Support:** TCP, over IPv4 and IPv6: between client and server, from external clients and to destinations. Options take IPv6 addresses with or without brackets, e.g. `::1` or `[::1]`.
- **Connection Model:** Each client gets its own TCP port on the server. Several clients can share a server, each with its own PSK and ports, and clients can share a port as standby, see [Several Clients and Standby](#several-clients-and-standby).
- **Scalability:** Not yet optimized for extremely high concurrency, a client forwards at most 512 connections at the same time by default.
- **Reliability:** The client reconnects on its own, see [Reconnects and Exit Codes](#reconnects-and-exit-codes). Aborted connections are passed on: if one side resets its TCP connection, or the tunnel breaks down, the other side's connection is reset, too, so truncated transfers don't look complete.
- **Security:** We try our best but no guarantees, see the known limitations in [SECURITY](SECURITY.md#known-limitations).

## License

This project is licensed under the [GPL-3.0-only](LICENSE) license.
