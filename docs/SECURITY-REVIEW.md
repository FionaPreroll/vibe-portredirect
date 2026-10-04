# Security Review

An internal review of the protocol and the code before 1.0 ([#29](https://github.com/FionaPreroll/vibe-portredirect/issues/29)).
It doesn't replace a review by someone outside the project, which #29 asks for, but prepares it: it says what was looked at, how, and what was found.

[SECURITY.md](../SECURITY.md) describes the security model and the known limitations, [PROTOCOL.md](PROTOCOL.md) the protocol.

## Scope

- **Version:** 0.7.0 with the changes up to this review: the rate limit for new forwarded connections (#25) and certificate fingerprints (#30).
- **Protocol:** authentication, setting up the tunnel, control messages, data streams, close codes and limits.
- **Code:** everything in `src/` that handles input from the network, configuration files, PSKs, keys and certificates, logs and metrics.
- **Dependencies:** their features, licenses, sources and known advisories.
- **Not in scope:** the implementations of QUIC (quinn), TLS (rustls) and the cryptography (ring), the operating system, and how releases are built.

## Method

- **Attack paths:** reading the code along what each party can do:
  - anyone who can reach the server's QUIC port, before and during authentication;
  - an authenticated client;
  - anyone who can reach a forwarded TCP port;
  - a server, towards its clients.
- **Fuzzing:** of all parsers of input from the peer, see [fuzz/](../fuzz/README.md).
  - Seven targets cover the authentication on both sides, HELLO, WELCOME, the control messages, the header of data streams, and parameters.
  - Each ran for two minutes, i.e. 0.4 million (control messages) to 12 million inputs, without findings.
  - They now run in CI: for 30 seconds each on pull requests, for 15 minutes each once a week.
- **Tools:**
  - `cargo deny`: advisories, licenses and sources, now in CI;
  - CodeQL on every pull request;
  - clippy;
  - the unit and end-to-end tests.

## Findings

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Peers could add lines to the other side's log | Low | Fixed |
| 2 | Each connection could buffer 1.25 MB of datagrams before authentication | Low | Fixed |
| 3 | 23 unused crates through a default feature of quinn | Informational | Fixed |
| 4 | Nothing ruled out unsafe code | Informational | Fixed |
| 5 | Before authentication, a client can fill the control stream's receive window | Low | Fixed by #27 |

### 1. Peers could add lines to the other side's log

- **What:** a peer can close a QUIC connection with a reason, any text. quinn makes the reason part of the error, and PortRedirect logs such errors, e.g. the server: `Incoming connection dropped: … closed by peer: <reason>`.
- **Who:** any client, before it authenticates, as the TLS handshake needs no client certificate. Also the server, towards its clients.
- **Impact:** tracing-subscriber escapes ANSI escape sequences, but not line breaks. So a client could add lines to the server's log that look like the server's own, e.g. that a client authenticated, and mislead whoever reads the log. The tunnel itself isn't affected.
- **Fix:** both programs format all fields of their log messages, including the message itself, with control characters escaped, e.g. a line break as `\n` (`escaping_fields` in `src/lib.rs`). This also covers errors logged in the future. A test logs such a reason and checks that it stays on one line.

### 2. Each connection could buffer 1.25 MB of datagrams before authentication

- **What:** quinn accepts QUIC datagrams by default, and keeps up to 1.25 MB of them per connection until they are read. PortRedirect reads no datagrams.
- **Impact:** a client could make the server keep 1.25 MB per connection before it authenticates. With the default limit of 64 QUIC connections, that is 80 MB.
- **Fix:** neither side accepts datagrams any more, so the peer can't send any. A test checks this on both sides.

### 3. 23 unused crates through a default feature of quinn

- **What:** quinn's default features include `platform-verifier`, which verifies certificates with the operating system's trust store. PortRedirect doesn't use it: clients trust exactly the server's certificate.
- **Impact:** 23 crates more to build and trust, e.g. `jni`, `security-framework`, `schannel` and `rustls-native-certs`.
- **Fix:** quinn is used without its default features, with only the features PortRedirect needs.

### 4. Nothing ruled out unsafe code

- **What:** the crate has no unsafe code, but nothing kept it that way.
- **Fix:** `#![forbid(unsafe_code)]`.

### 5. Before authentication, a client can fill the control stream's receive window

- **What:** the server reads only the authentication messages from the control stream until the client is authenticated. A client may send more, which quinn keeps until it is read, up to the stream's receive window of 1.25 MB.
- **Impact:** up to 1.25 MB per connection before authentication, 80 MB with the default limit of 64 QUIC connections. The limits per address (8 QUIC connections by default) and the timeouts (10 seconds each for the TLS handshake and the authentication) keep it short and spread out.
- **Status:** fixed by [#27](https://github.com/FionaPreroll/vibe-portredirect/issues/27), which made the stream windows larger for throughput: 8 MiB, which would have made this worse. Until the client has authenticated, the server's receive window for the whole connection is now 64 KiB; then it grows to the full 32 MiB. Tests check both, with the server's authentication.

## Checked without Findings

- **Authentication** (`src/protocol/auth.rs`):
  - The proofs are HMAC-SHA256 tags keyed with the PSK, over a label, keying material exported from the TLS session, a 32-byte nonce from the operating system's random number generator, and the client's name.
  - The labels differ by direction, and the exporter label names the protocol version.
  - The client proves its knowledge first, and verifies the server's proof.
  - Proofs are verified in constant time (`ring::hmac::verify`). For an unknown name, the server verifies the proof with random PSKs, the same number as for a known name, so the time doesn't reveal which names exist.
- **Parsers:**
  - Lengths are checked before memory is allocated: names have at most 64 bytes, messages and data stream headers at most 1024.
  - Unknown message types, over-long messages and malformed parameters are protocol violations, which close the connection.
  - The buffer for incomplete control messages holds at most one message and one read.
- **TLS and QUIC:**
  - Only TLS 1.3, as rustls is built without TLS 1.2.
  - The ALPN protocol is required, and names the protocol version (`pr-5`).
  - Clients can't open streams on the server.
  - Early data (0-RTT) is off on both sides.
  - The server validates client addresses with QUIC's Retry before it starts the handshake.
- **Certificates:**
  - The client's verifier for fingerprints only replaces the check of the certificate chain. The server still has to sign the handshake with the certificate's key; tests check that another key fails.
  - The private key is written readable by its owner only, in a private directory.
- **PSKs:**
  - Held in `SecretString`, which isn't logged.
  - Configuration files hold the paths of PSK files, not PSKs.
  - Warnings for PSKs on the command line, short PSKs, and PSK files that other users can read.
- **Limits:**
  - QUIC connections, in total and per address.
  - Timeouts for the TLS handshake and the authentication.
  - Blocking addresses after failed attempts.
  - Forwarded connections per client and per address, a rate limit for new ones, and an idle timeout.
- **Metrics:**
  - Labels only hold the names of configured clients, never names an unauthenticated client sent, so a client can't add labels.
  - The endpoints listen on `127.0.0.1` by default, and time out requests whose header doesn't arrive.
- **Client:**
  - It only connects to its configured destination, for at most `--max-connections` streams at a time.
  - The server can't make it connect elsewhere.
- **Supply chain:**
  - `Cargo.lock` is committed, and CI builds with `--locked`.
  - GitHub Actions are pinned to commits.
  - Dependabot updates dependencies and actions.
  - `cargo audit` and now `cargo deny` check advisories, and CodeQL the code.

## Known Limitations

These remain as described in [SECURITY.md](../SECURITY.md):

- **A leaked private key and a weak PSK:** whoever has the server's private key gets the clients' proofs, and could guess a weak PSK offline.
- **Distributed attacks:** limits apply per address, so many addresses add up.
- **No access control on the metrics endpoints:** they rely on listening on `127.0.0.1`.

## For the External Review

Suggested focus:

- The authentication protocol, and how it binds proofs to the TLS session, also with session resumption ([PROTOCOL.md](PROTOCOL.md), `src/protocol/auth.rs`).
- The certificate verifier for fingerprints (`src/quic/fingerprint.rs`), and whether pinning the certificate rather than its key is adequate.
- Resource use under attack from many addresses, and the limits' defaults ([Limits](PROTOCOL.md#limits)).
