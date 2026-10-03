# Changelog

All notable changes to PortRedirect are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

Server and client must speak the same protocol version, see [docs/PROTOCOL.md](docs/PROTOCOL.md).
When a version changes the protocol, update the server and all its clients together.

Versions 0.4.0 to 0.6.0 were not published on crates.io; the latest published version is 0.3.0.

## [Unreleased]

### Added

- `--version` for both programs.

### Changed

- Logs go to stderr instead of stdout, with colors only on a terminal.
- The `RUST_LOG` environment variable, if set, takes precedence over `--log-level` and can set levels per module, e.g. `RUST_LOG=info,portredirect::forward=debug`.

### Removed

- The server's deprecated `--local-port`; use `--allowed-client-ports`.

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
