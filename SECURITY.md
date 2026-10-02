# Security Policy

## Supported Versions

PortRedirect is not stable yet (versions < 1.0).
Security fixes are made on the latest code (`main` branch) only, there are no maintained release branches.
There are no guarantees, see the [license](LICENSE).

## Reporting a Vulnerability

Please **do not open a public issue** for security problems.
Report them privately via GitHub instead: on the repository page, go to the **Security** tab and click **Report a vulnerability**.
Include the version or commit, your setup and the steps to reproduce.

Bugs without security impact can be reported as normal issues.

## Security Model

What PortRedirect is designed to protect, and under which assumptions.
The wire protocol is described in [docs/PROTOCOL.md](docs/PROTOCOL.md).

**Assets:** the forwarded data, the destination service behind the client, and the server's TCP ports.

**Trust assumptions:**

- The server's private key (`key.der`) stays on the server. The client trusts exactly the certificate it was given (`cert.der`); whoever has the private key can impersonate the server.
- The pre-shared key (PSK) is known only to the server and its clients, and is long and random (see the README).
- Both machines themselves are trusted: anyone with access to the server process, the client process or their files can read the PSK and the forwarded data.

**What the tunnel provides:**

- Confidentiality and integrity of the forwarded data between client and server (QUIC with TLS 1.3).
- The client only connects to the server whose certificate it holds.
- Only clients that know the PSK can make the server listen on a TCP port, and only on ports allowed by `--allowed-client-ports`.
  Before authentication, a client cannot open streams or cause the server to open TCP ports.

**What it does not provide:**

- Protection of the forwarded data outside the tunnel: between the external TCP client and the server, and between the client and the destination, data is forwarded as is. Use an end-to-end protocol such as TLS (e.g. HTTPS) for sensitive data.
- Access control for the forwarded port: everyone who can reach the server's TCP port reaches the destination service. The destination does not see the external client's address.

## Known Limitations

These are known weaknesses that are not fixed yet. Take them into account when you expose PortRedirect to untrusted networks.

- **Connection exhaustion:** a client accepts at most 100 concurrent forwarded connections, and idle forwarded connections never time out. Anyone who can reach the server's TCP port can block it by opening 100 idle connections.
- **No rate limiting:** the server neither limits the number of unauthenticated QUIC connections nor failed authentication attempts, and does not enforce a minimum PSK length. A weak PSK can be guessed online.
- **Authentication construction:** the PSK proof is SHA-512 over challenge and PSK instead of an HMAC, its comparison is not constant-time, and it is not bound to the TLS session. No practical attack is known, as each connection gets a fresh random challenge and one attempt, but standard constructions should be used.
- **No reconnect:** the client exits when the connection to the server is lost, with exit code 0. Use a service manager that restarts it unconditionally (e.g. systemd `Restart=always`).
- **Aborted connections look complete:** if a TCP connection is reset on one side, the other side sees a normal end of stream instead of a reset, so truncated transfers are not signalled as errors.
- **Metrics endpoint:** with `--provide-metrics`, the client serves Prometheus metrics on `0.0.0.0:9898` without authentication. Restrict access to it with a firewall.
- **Logging:** both programs log at debug level, including peer addresses, and the log level is not configurable yet.
