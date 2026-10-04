# Changelog

All notable changes to PortRedirect are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

Server and client must speak the same protocol version, see [docs/PROTOCOL.md](docs/PROTOCOL.md).
When a version changes the protocol, update the server and all its clients together.

Versions 0.4.0 to 0.7.0 were not published on crates.io; the latest published version is 0.3.0.

## [Unreleased]

### Added

- Both programs can read their settings from a TOML configuration file, `--config-file`. Its keys are the names of the options, and options on the command line or in the environment take precedence. It only names the files that hold PSKs, and relative paths in it are relative to the file. Unknown keys are errors, so typos don't go unnoticed. See the README.
- Graceful shutdown: on `SIGINT` or `SIGTERM`, both programs start no new forwarded connections and send `DRAIN`, let running ones finish for up to `--shutdown-timeout` seconds (default 5), and then close the rest. A second signal closes them right away. A client that shuts down makes the server release its port right away, e.g. for a standby client, and a server that shuts down refuses new clients.
- The server serves Prometheus metrics, too: `--provide-metrics` and `--metrics-listen`, on `127.0.0.1:9899` by default. Metrics of its clients have the label `client`. New metrics include failed authentication attempts, refused QUIC connections by reason, and gauges of the running tunnels and forwarded connections on both sides, e.g. the client's `portredirect_client_tunnel_up`. The README lists all metrics.
- A rate limit for new forwarded connections per external address (IPv6: per /64 network): after `--max-connection-burst-per-ip` at once (default 64), at most `--max-connection-rate-per-ip` per second (default 20). Further connections are closed right away and counted in `portredirect_server_forwarded_connections_refused_total` with the label `reason="rate_limit"`; the address limit counts as `reason="address_limit"`. Each forwarded connection makes the client connect to the destination, so this limits the load a single host can put on it.
- Clients can trust the server's certificate by its SHA-256 fingerprint, `--quic-cert-fingerprint`, instead of a copy of `cert.der`, and by several fingerprints while the server's certificate changes. The server logs its certificate's fingerprint when it starts, and `--print-quic-cert-fingerprint` prints it, generating the certificate first if there is none. The README describes how to change the server's certificate.
- The server's configuration file can list several clients, each with its own name, one or two PSK files (two while changing the PSK) and ports. A client can only use its own ports. Clients may share ports on purpose, e.g. an active and a standby client; the server logs which clients share which ports when it starts.
- Fuzz targets for the parsers of the protocol, for cargo-fuzz in `fuzz/`: the authentication on both sides, `HELLO`, `WELCOME`, the control messages and the header of data streams. CI runs each for 30 seconds on pull requests and for 15 minutes once a week, and `cargo test` runs a short smoke test of them on stable Rust.
- CI checks the dependencies with cargo-deny: known vulnerabilities, licenses that don't go with the GPL, and sources other than crates.io (`deny.toml`, `make deny`).
- [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md): the internal security review before 1.0, with what was looked at, how, and what was found.
- `--congestion-control bbr`, for both programs and in their configuration files: BBR instead of CUBIC decides how fast a side sends. On links that lose packets for other reasons than congestion, it is much faster: with 1 % loss, the tunnel kept 176 to 1300 Mbit/s instead of less than 4. Set it on both sides; quinn marks BBR experimental.
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md): measurements over links with 50 and 150 ms round-trip time and 1 % loss, and the chosen values. `examples/link_emulator.rs` emulates such links without privileges, `utils/link_benchmark.py` runs the measurements, and a BATS test checks that data crosses such a link unchanged.
- Prebuilt binaries for Linux on x86_64, 64-bit ARM and 32-bit ARM (ARMv7) of the latest commit on `main`, in the pre-release `latest`: by default for glibc 2.17 or newer, and linked statically with musl for any distribution. For each commit, CI builds them, runs the tests for their architecture and replaces the previous ones, with checksums and build provenance attestations. See the README.

### Changed

- Options renamed for consistency before 1.0. The old names are no longer accepted, the programs exit with a message naming the new name. Update service files and scripts together with the programs:
  - `--quic-psk`, `--quic-psk-file` and `PORTREDIRECT_QUIC_PSK` are now `--psk`, `--psk-file` and `PORTREDIRECT_PSK`: the PSK authenticates the client and isn't specific to QUIC.
  - The client's `--quic-remote-hostname-match` is now `--quic-cert-hostname`, like the server option whose value it must match.
  - The server's `--local-host` is now `--listen-host`, matching the client's `--remote-listen-port`, and `--quic-server-host` and `--quic-server-port` are now `--quic-listen-host` and `--quic-listen-port`.

- Metric names are consistent before 1.0: they start with `portredirect_client_` or `portredirect_server_` and say what they count, e.g. `portredirect_client_bytes_to_destination_total` instead of `bytes_transmitted_b_total`. All metrics are listed from the start, with 0, and each program only serves its own. Update dashboards and alerts, see the README for the new names.
- `--print-metrics` prints the server's metrics under their new names, each summed over all clients.
- Log messages of the programs' main functions, e.g. the client's fatal errors, have the target `portredirect::client::main` or `portredirect::server::main` instead of `portredirect_client` or `portredirect_server`. Update `RUST_LOG` filters that name the programs.
- Neither side accepts QUIC datagrams any more, which PortRedirect doesn't use: a client could make the server keep up to 1.25 MB of them per connection, even before it authenticated.
- quinn is built without its platform verifier, which PortRedirect doesn't use, as clients trust exactly the server's certificate: 23 fewer dependencies.
- Larger QUIC flow-control windows: a single forwarded connection reaches about 1 Gbit/s at 50 ms round-trip time and 390 Mbit/s at 150 ms, instead of 116 and 61 Mbit/s. Each side keeps at most 32 MiB of received data per tunnel.
- Both programs ask for 4 MiB UDP socket buffers, so datagrams that arrive in bursts aren't lost, which slowed down fast connections. They log a hint if the operating system allows less; on Linux, raise `net.core.rmem_max` and `net.core.wmem_max`, see the README.
- Until a client has authenticated, the server lets it send only 64 KiB that it hasn't read yet.

### Removed

- The library's public API. The crate's library only holds the code of the two programs, so their internals can change in any release, also from 1.0 on. Version 0.3.0 on crates.io still exported them.

### Fixed

- A client with a wrong PSK could take the server's rejection for a temporary failure and keep reconnecting, if the end of its control stream arrived before the reason. The server now closes the connection with the reason first, also after an authentication timeout.
- A client that stalled the TLS handshake, e.g. on purpose, held up all new connections to the server as long as the handshake lasted, 30 seconds for a client that stopped responding, because the server completed each handshake before accepting the next connection. Handshakes now run independently and are aborted after 10 seconds, which counts as a failed attempt for blocking the address.
- Text from the peer could add lines to the other side's log: e.g. a client, even before authenticating, could close its connection with a reason that contains line breaks, which the server logged as part of the error, and make the lines look like the server's own. Log messages now escape control characters, e.g. a line break as `\n`.

## [0.7.0] - 2026-10-03

Protocol version 5 (`pr-5`), incompatible with 0.6.0. It is designed to stay compatible from 1.0 on, see [docs/PROTOCOL.md](docs/PROTOCOL.md#versions-and-compatibility).

### Added

- Clients authenticate with a name, `--client-name` (default `default`). A server configured on the command line has a single client of that name. The server can tell several clients apart, each with its own PSKs and ports, e.g. an active and a standby client for the same port; configuring them follows with a configuration file.
- A client that connects again while the server still holds the port for its previous connection, e.g. after a crash, replaces that connection right away instead of waiting up to 30 seconds. A second running instance with the same name exits with code 1.
- Aborted connections are passed on: if one side resets its TCP connection, or the tunnel ends while connections are forwarded, the other side resets its connection, too, instead of closing it normally. Truncated transfers no longer look complete.
- Messages on the control stream have a type and a length, and consist of parameters that receivers skip if they don't know them. So later versions can add optional features without breaking compatibility.
- `DRAIN` messages, for shutting down without breaking running connections. Both programs understand them, but don't send them yet.
- Server and client log each other's software and version.
- `--version` for both programs.

### Changed

- External connections that can't be forwarded, e.g. because the destination is unreachable, are reset instead of closed normally.
- Logs go to stderr instead of stdout, with colors only on a terminal.
- The `RUST_LOG` environment variable, if set, takes precedence over `--log-level` and can set levels per module, e.g. `RUST_LOG=info,portredirect::forward=debug`.

### Removed

- The server's deprecated `--local-port`; use `--allowed-client-ports`.
- The `BYE` message, which no client sent; closing the connection says the same.

## [0.6.0] - 2026-10-03

Protocol version 4 (`pr-4`), incompatible with 0.5.0.

### Added

- The server starts each data stream with a header naming the external client. The client logs the address at debug level.
- The server's `--print-metrics` counts client connections (`clients_connected`, `clients_closed`) and keepalive timeouts (`keepalive_err`).
- `make coverage` measures the test coverage.

### Changed

- Updated rcgen to 0.14 and dirs to 7.
- The server's `--print-metrics` shows `clients_connected` and `clients_closed` instead of `server_opened` and `server_closed`, which were never updated.

### Fixed

- Protocols in which the server speaks first, e.g. SMTP, POP3 or FTP, hung: the client learned about a forwarded connection only when the external client sent data.
- Port 0 could be allowed, e.g. in the range `0-1000`; a client requesting it made the server listen on a random port. Port 0 is now never allowed.
- If only one of `cert.der` and `key.der` existed, the server generated a new pair and replaced the remaining file, so clients no longer trusted it. Now the server doesn't start and names the file to restore.
- An invalid `--quic-cert-hostname`, e.g. with non-ASCII characters, made the server panic.
- The normal end of a stream by the peer was recognized by the text of quinn's error message instead of its type.
- Reconnection delays could overflow with a very large maximum (library API only).

## [0.5.0] - 2026-10-03

Protocol version 3 (`pr-3`), incompatible with 0.4.0.

### Added

- Mutual authentication: client and server prove that they know the PSK with HMAC-SHA256, bound to the TLS session.
- Limits on the server: `--max-quic-connections`, `--max-connections`, `--max-connections-per-ip` and `--idle-timeout`. Addresses are blocked for 10 minutes after 5 failed handshakes or authentication attempts within 10 minutes.
- The client reconnects with growing delays whenever the connection ends, and exits with code 1 on errors that retrying can't fix, 0 on SIGINT or SIGTERM and 2 on invalid arguments.
- Both programs close their connections on SIGINT or SIGTERM, so the peer notices right away.
- Connections are closed with codes that say why, see docs/PROTOCOL.md.
- `--log-level` for both programs, `--metrics-listen` and `--config-dir` for the client.

### Changed

- The client's metrics endpoint listens on `127.0.0.1:9898` by default instead of all addresses.
- The default log level is `info` instead of `debug`.
- The client exits with code 1 on permanent errors; before, it always exited with code 0 when the connection ended.

## [0.4.0] - 2026-10-03

Protocol version 2 (`pr-2`), incompatible with 0.3.0.

### Added

- The client's `--remote-listen-port` names the port the server should listen on; the server confirms it.
- The PSK can come from a file (`--quic-psk-file`) or the `PORTREDIRECT_QUIC_PSK` environment variable.
- docs/PROTOCOL.md and a security model in SECURITY.md.

### Changed

- Updated dependencies; `cargo audit` reported 17 vulnerabilities before, none after. The minimum supported Rust version is now 1.88.
- The client's metrics endpoint uses hyper 1 instead of warp.
- The server creates its private key readable only by its owner and warns about secret files other users can read.

### Fixed

- The tunnel didn't work: the client never requested a listen port, so every connection ended in a configuration timeout.
- `--quic-remote-hostname-match` was ignored.

## [0.3.0]

The latest version published on crates.io. Protocol version 1 (`pr-1`).
