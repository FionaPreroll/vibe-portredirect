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
- The server's configuration file can list several clients, each with its own name, one or two PSK files (two while changing the PSK) and ports. A client can only use its own ports. Clients may share ports on purpose, e.g. an active and a standby client; the server logs which clients share which ports when it starts.

### Changed

- Options renamed for consistency before 1.0. The old names are no longer accepted, the programs exit with a message naming the new name. Update service files and scripts together with the programs:
  - `--quic-psk`, `--quic-psk-file` and `PORTREDIRECT_QUIC_PSK` are now `--psk`, `--psk-file` and `PORTREDIRECT_PSK`: the PSK authenticates the client and isn't specific to QUIC.
  - The client's `--quic-remote-hostname-match` is now `--quic-cert-hostname`, like the server option whose value it must match.
  - The server's `--local-host` is now `--listen-host`, matching the client's `--remote-listen-port`, and `--quic-server-host` and `--quic-server-port` are now `--quic-listen-host` and `--quic-listen-port`.

### Fixed

- A client that stalled the TLS handshake, e.g. on purpose, held up all new connections to the server as long as the handshake lasted, 30 seconds for a client that stopped responding, because the server completed each handshake before accepting the next connection. Handshakes now run independently and are aborted after 10 seconds, which counts as a failed attempt for blocking the address.

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
