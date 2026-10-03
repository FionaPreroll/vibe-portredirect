# PortRedirect

*Glue your frontend to the backend!*

![PortRedirect Logo showing a green pipe with the text superimposed with golden color](./docs/portredirect_logo.png)

## Introduction

PortRedirect is a lightweight user-space TCP forwarder that bridges your frontend and backend via a secure QUIC tunnel. It has two components:

- **Server:** Listens for incoming TCP connections (e.g., on port 443) and tunnels them over a persistent QUIC connection.
- **Client:** Connects to the QUIC server, receives tunneled streams, and forwards them to the target TCP service (e.g., `localhost:4433`).

Both use a pre-shared key (PSK) for authentication. The server auto-generates a self-signed certificate and private key on first run (stored in `~/.config/portredirect`), which the client uses to verify the server.

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

Build both binaries from a checkout of this repository (requires Rust 1.88 or newer):

```sh
cargo install --locked --path .
```

`--locked` uses the dependency versions from `Cargo.lock`, which are the ones tested and audited in CI.

> **Note:** The `portredirect` package on crates.io is published by the original project (see [History](#history)). Its version 0.3.0 predates protocol version 2 (see [docs/PROTOCOL.md](docs/PROTOCOL.md)) and can't talk to this version. Server and client must speak the same protocol version.

## Usage

### Running the Frontend Server

For example, if your public server (accessible on TCP port 443) should forward traffic over a VPN (with an internal IP of `10.0.0.1`) on port 12345, run:

```sh
portredirect_server \
    --local-host 0.0.0.0 --allowed-client-ports 443 \
    --quic-server-host 10.0.0.1 --quic-server-port 12345 \
    --quic-cert-hostname 10.0.0.1 \
    --quic-psk-file /etc/portredirect/psk
```

**Parameters:**

- **`--local-host`:** Where to listen for incoming TCP connections.
- **`--allowed-client-ports`:** TCP ports clients may ask the server to listen on, e.g. `443` or `80,443,8000-8100`.
- **`--quic-server-host` & `--quic-server-port`:** Where to listen for the QUIC tunnel (UDP).
- **`--quic-cert-hostname`:** IP address or DNS name the generated certificate is issued for, the client verifies it. Only used when the certificate is generated on first start (default `127.0.0.1`).
- **`--quic-psk-file`:** File containing the pre-shared key, see [PSK Best Practices](#psk-best-practices).
- **`--config-dir`:** Where the certificate and private key are stored (default `~/.config/portredirect`).
- **`--print-metrics`:** Print connection and traffic counters to stderr when they change.

### Running the Backend Client

To forward traffic to a local service (e.g., an `nginx` server on `127.0.0.1:4433`), run:

```sh
portredirect_client \
    --destination-host 127.0.0.1 --destination-port 4433 \
    --remote-listen-port 443 \
    --quic-remote-host 10.0.0.1 --quic-remote-port 12345 \
    --quic-psk-file /etc/portredirect/psk
```

**Parameters:**

- **`--destination-host` & `--destination-port`:** The target TCP service.
- **`--remote-listen-port`:** The TCP port the server should listen on for you. Must be one of the server's `--allowed-client-ports`.
- **`--quic-remote-host` & `--quic-remote-port`:** The QUIC server’s address.
- **`--quic-remote-hostname-match`** (optional): Name the server's certificate must be issued for, if it differs from `--quic-remote-host`. Must match the server's `--quic-cert-hostname`.
- **`--quic-psk-file`:** File containing the pre-shared key, must match the server’s PSK.
- **`--provide-metrics`:** Serve Prometheus metrics at `http://0.0.0.0:9898/metrics`. The endpoint has no authentication, restrict access to it.

> **Important:** Start the server first to generate its certificate, then copy **only the certificate** `~/.config/portredirect/cert.der` from the server to the same path on the client machine.
> Never copy the private key `key.der`: anyone who has it can impersonate your server. The server creates it readable only by its owner (mode `0600`) and warns if it is accessible by others.

### PSK Best Practices

Always use a long, random pre-shared key when operating over untrusted networks. Generate it once and store it in a file that only the user running PortRedirect can read, then copy that file to the other machine via a secure channel:

```sh
(umask 077 && mkdir -p /etc/portredirect && openssl rand -hex 32 > /etc/portredirect/psk)
```

Both programs accept the PSK from one of these sources:

- **`--quic-psk-file <PATH>`** (recommended): Reads the PSK from a file, trailing line breaks are ignored. PortRedirect warns if the file is accessible by other users.
- **`PORTREDIRECT_QUIC_PSK`** environment variable: Useful for container or service managers that inject secrets.
- **`--quic-psk <PSK>`**: Avoid this outside of testing. Command-line arguments are visible to every local user in the process list (`ps`, `/proc/<pid>/cmdline`) and end up in shell histories, so PortRedirect warns when it is used.

## Authentication & Certificate Verification

PortRedirect secures QUIC tunnels using auto-generated certificates and a PSK-based challenge-response system. The client verifies the server’s certificate, while the server challenges the client to prove its identity with the shared PSK.
Only after that, the server opens the TCP port the client asked for.

- [docs/PROTOCOL.md](docs/PROTOCOL.md) describes the protocol in detail.
- [SECURITY.md](SECURITY.md) describes the security model, known limitations and how to report vulnerabilities.

## Development

### Getting Started

To get an overview of the codebase, use [ARCHITECTURE.md](./ARCHITECTURE.md) as an entry point.

### Tests

Run the Cargo tests and the Python unit tests of the benchmark utilities:

```sh
make test
```

The Cargo tests include end-to-end tests of a complete tunnel in `tests/tunnel_end_to_end.rs`.

Before committing, run the linters (`cargo fmt --check`, `cargo clippy` and, if installed, `black`):

```sh
make lint
```

### BATS Tests

The BATS tests run the release binaries with real tools (`iperf3`, `nc`, `pv`, `curl` and the Python utilities in `utils/`).
Install [BATS-Core](https://github.com/bats-core/bats-core) and these tools, then run all of them with `make test_bats`, or a single one with:

```sh
bats tests/<test_file.bats>
```

## Command-Line Help

For a complete list of options:

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

- **Protocol Support:** Currently supports IPv4 and TCP.
- **Connection Model:** Each client gets its own TCP port on the server. Several clients can share a server if it allows several ports.
- **Scalability:** Not yet optimized for extremely high concurrency, a client forwards at most 100 connections at the same time.
- **Reliability:** The client does not reconnect yet, run it with a service manager that restarts it.
- **Security:** We try our best but no guarantees, see the known limitations in [SECURITY](SECURITY.md#known-limitations).

## History

This project independently continues the development of [unspezifisch/portredirect](https://github.com/unspezifisch/portredirect).
Thanks to unspezifisch for creating PortRedirect.

## License

This project is licensed under the [GPL-3.0-only](LICENSE) license.
