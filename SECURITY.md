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

- The server's private key (`key.der`) stays on the server. The client trusts exactly the certificates it was given, by their SHA-256 fingerprints (`--quic-cert-fingerprint`) or as a copy (`cert.der`).
  Whoever has the private key can make clients connect to them, but can't complete the authentication without the PSK.
  They do get the clients' proofs of the PSK, though, so a weak PSK could be guessed offline.
  If the private key may have been exposed, change the certificate as the README describes, and remove the old fingerprint from all clients: until then, they still trust it.
- The pre-shared key (PSK) is known only to the server and its clients, and is long and random (see the README).
  PortRedirect warns about PSKs shorter than 16 bytes, but accepts them.
  Clients authenticate with a name and the PSK of that name. Give each client its own name and PSK in the server's configuration file: then a client may only use the ports listed for its name, and only clients with the same name can replace each other's connections. A server configured with a single PSK and `--allowed-client-ports` has a single client, `default`: all clients that know its PSK may use all allowed ports and can replace each other's connections.
  Configuration files hold no PSKs, only the paths of the files with the PSKs, which should be readable only by the user running PortRedirect.
- Both machines themselves are trusted: anyone with access to the server process, the client process or their files can read the PSK and the forwarded data.

**What the tunnel provides:**

- Confidentiality and integrity of the forwarded data between client and server (QUIC with TLS 1.3).
- Mutual authentication: the client only uses a server that has the private key of a certificate it trusts and proves that it knows the client's PSK.
  Only clients that know the PSK of their name can make the server listen on a TCP port, and only on the ports allowed for that name.
  Before authentication, a client cannot open streams or cause the server to open TCP ports.
- The proofs of the PSK are HMACs bound to the TLS session and the client's name, so they can't be replayed or relayed into another connection, and are verified in constant time.
  An unknown name fails like a wrong PSK, in the same time, so the server doesn't reveal which names exist.
- Online guessing of the PSK is slow: an address is blocked for 10 minutes after 5 failed attempts within 10 minutes.
- Limits on the resources a single host can use: QUIC connections, forwarded connections per client and per external address, and the time a forwarded connection may stay idle.
  A client that stalls the TLS handshake doesn't hold up other clients; the server closes its connection after 10 seconds.
  See [Limits](docs/PROTOCOL.md#limits) for the defaults and options.

**What it does not provide:**

- Protection of the forwarded data outside the tunnel: between the external TCP client and the server, and between the client and the destination, data is forwarded as is. Use an end-to-end protocol such as TLS (e.g. HTTPS) for sensitive data.
- Access control for the forwarded port: everyone who can reach the server's TCP port reaches the destination service. The destination does not see the external client's address.
- Access control for the metrics endpoints (`--provide-metrics`): they listen on `127.0.0.1` by default; make them reachable from trusted networks only. The server's metrics name its clients.

## Known Limitations

These are known weaknesses that are not fixed yet. Take them into account when you expose PortRedirect to untrusted networks.

- **Distributed attacks:** the limits apply per address (IPv6: per /64 network). An attacker with many addresses can still use up the server's QUIC connections (`--max-quic-connections`) or a client's forwarded connections (`--max-connections`), and keep guessing the PSK online from each of them. A long random PSK makes guessing hopeless anyway.
- **No rate limit for new forwarded connections:** the number of concurrent forwarded connections is limited, but not how fast new ones are opened. Each of them makes the client connect to the destination.
