# PortRedirect Protocol (version 4)

This document describes how `portredirect_client` and `portredirect_server` talk to each other.
It reflects the implementation in `src/protocol/` and `src/quic/`; if they disagree, the code wins and this document needs fixing.

## Overview

```text
 external TCP client          portredirect_server              portredirect_client          destination
        |                            |   <== QUIC connection ==    |                            |
        |                            |   control stream: auth,     |                            |
        |                            |   listen port, keepalive    |                            |
        |-- TCP connect ------------>|                             |                            |
        |                            |-- open data stream -------->|-- TCP connect ------------>|
        |<=========== bytes =========|=========== bytes ===========|=========== bytes =========>|
```

1. The client connects to the server via QUIC and verifies the server's certificate.
2. The server opens the **control stream**. Client and server prove to each other that they know the pre-shared key (PSK).
3. The client asks the server to listen on a TCP port; the server binds it and confirms.
4. For every external TCP connection the server accepts, it opens a **data stream** to the client and names the external client in a header. The client connects to the destination and forwards bytes in both directions.
5. The client sends keepalive messages on the control stream for as long as the tunnel should exist.
6. A side that ends the connection closes it with a [close code](#close-codes) that tells why. The client connects again, unless the code means that connecting again would fail the same way.

## Transport

- QUIC with TLS 1.3, ALPN protocol identifier `pr-4`.
  The identifier changes with every incompatible protocol change; peers speaking a different version fail the TLS handshake ("peer doesn't support any known protocol").
  Version 3 (`pr-3`, PortRedirect 0.5.0) started data streams without a header, so the client learned about a forwarded connection only when the external client sent data: protocols in which the server speaks first, e.g. SMTP, hung.
  Version 2 (`pr-2`, PortRedirect 0.4.0) authenticated only the client, without binding the proof to the TLS session, and closed all connections with code 0.
  Version 1 (`pr-1`, e.g. `portredirect` 0.3.0 on crates.io) had no listen port negotiation.
- **Server authentication:** the server presents a certificate, by default a self-signed one it generates on first start (`cert.der`, `key.der` in its configuration directory).
  The client trusts exactly the certificate in its own `cert.der` (copied from the server) and verifies that it is issued for `--quic-remote-hostname-match`, or for the IP address of `--quic-remote-host` if not given.
  In addition, the server proves on the control stream that it knows the PSK.
- **Client authentication:** none at the TLS level; the client proves on the control stream that it knows the PSK, see below.
- **Streams:** only the server opens streams, all of them bidirectional.
  The server allows the client to open zero streams, so a client cannot send anything except on streams the server opened.
  The client accepts one stream more than its `--max-connections`, for the control stream.
- **Address validation:** the server answers new connections with a stateless retry, so a client must be able to receive packets at its source address before the server keeps state for it.
- **Admission control:** the server refuses connections beyond its [limits](#limits), and from addresses that failed to authenticate repeatedly, before the TLS handshake.
- Further transport settings: both sides send QUIC keep-alive packets every 25 s, the idle timeout is 30 s (Quinn default), the spin bit is disabled; the server schedules its streams round-robin.

## Control stream

The first stream of a connection is opened by the server and stays open for the connection's lifetime.
Messages are ASCII text or fixed-size binary records, as shown below (`\n` is a line feed, `uN` an N-bit unsigned integer in network byte order, `[N]` N raw bytes).

If a side rejects anything, it closes the whole QUIC connection with a [close code](#close-codes).

### 1. Authentication

Both sides prove that they know the PSK, with proofs that are bound to the TLS session.

**Session binding:** both sides export 32 bytes of keying material from the TLS session ([RFC 8446, section 7.5](https://www.rfc-editor.org/rfc/rfc8446#section-7.5)), with the label `EXPORTER-portredirect-v3-authentication` and an empty context.
The value is the same on both ends of a connection and unique to it, so a proof is worthless in any other connection, e.g. when replayed or relayed.

**Proofs** are HMAC-SHA256 tags (32 bytes), keyed with the bytes of the PSK, over an ASCII label, the session binding and the nonce:

```text
client proof = HMAC-SHA256(PSK, "portredirect v3 client proof" || binding || nonce)
server proof = HMAC-SHA256(PSK, "portredirect v3 server proof" || binding || nonce)
```

(`||` is concatenation.) The labels differ, so a client proof can't serve as server proof or vice versa.

**Messages:**

1. Server to client, 41 bytes:

   ```text
   CHALLENGE <nonce: [32]>
   ```

   (no space; the literal `CHALLENGE` is followed directly by the nonce)
   `<nonce>` are 32 bytes from the operating system's secure random number generator.

2. Client to server, 40 bytes:

   ```text
   RESPONSE <client proof: [32]>
   ```

   If the proof is wrong, the server closes the connection with code 1 without sending anything else.

3. Server to client, 40 bytes:

   ```text
   ACCEPTED <server proof: [32]>
   ```

   If the proof is wrong, the client closes the connection with code 1.

Both sides verify proofs in constant time.
The client proves its knowledge first: anyone can connect to the server, but only a server with the certificate's private key gets a client's proof, so nobody else can use one to guess the PSK offline.
The server closes the connection with code 2 if authentication is not finished within 10 seconds.

**Example:** with the PSK `test-psk`, the binding bytes `0x00`, `0x01`, …, `0x1f` and the nonce bytes `0x20`, `0x21`, …, `0x3f`, the proofs are:

```text
client proof: d9183d723457d964b08ee797ee6f8e8d9555c3bcb88cf4aed96c597ac50dbfe1
server proof: 3e3e8adcd46b77001d02198f2981a38f0b57ada39b2e42588844a42b82b24139
```

### 2. Listen port

Client to server, 12 bytes:

```text
LISTENPORT <port: u16>
```

(no space; the literal `LISTENPORT` is followed directly by two bytes)

The server checks the port against its `--allowed-client-ports` (port 0 is never allowed, the system would choose a random port), binds a TCP listener on `--local-host` and that port, and answers with 11 bytes:

```text
LISTENING <bound port: u16>
```

(again without a space)

From now on, the server accepts external TCP connections on that port for this client.
On errors, the server closes the connection: with code 5 if the port is not allowed, 6 if it could not listen on the port (e.g. the port is in use, also by a previous connection of the same client that has not timed out yet), 3 for a malformed request and 4 if no request arrives within 10 seconds.

### 3. Keepalive

| Message     | Direction        | Meaning                                                   |
| ----------- | ---------------- | --------------------------------------------------------- |
| `PING\n`    | client to server | Sent right away and then every 30 seconds.                |
| `PONG\n`    | server to client | Answer to each `PING`.                                    |
| `BYE\n`     | client to server | Ends the connection. Not sent by the current client.      |

- The client closes the connection with code 7 if a `PONG` does not arrive within 30 seconds, or anything else arrives instead.
- The server ends the connection if it receives no message for 60 seconds (code 7), an unexpected or longer than 16 bytes message (code 3), `BYE` or the end of the control stream (code 0).
  It then stops the TCP listener and closes the connection.

## Data streams

For each external TCP connection the server accepts, it opens a new bidirectional stream and starts it with a header, server to client:

```text
CONNECTION <family: u8> <address: [4] or [16]> <port: u16>
```

(no spaces; 17 bytes for IPv4, 29 bytes for IPv6)

- `<family>`: 4 for IPv4, 6 for IPv6. IPv4-mapped IPv6 addresses are sent as IPv4.
- `<address>`, `<port>`: the external client's address and port, e.g. `192.0.2.1:50000` as `CONNECTION` followed by the bytes `04 c0 00 02 01 c3 50`.

QUIC announces a new stream to the peer only with its first data. So the header also makes the client learn about the connection right away, even if the external client waits for the destination to speak first, as in SMTP.
The client logs the external client's address (at debug level), but doesn't pass it on to the destination.

Then the client connects to its destination (`--destination-host`, `--destination-port`), and both sides copy bytes between the TCP connection and the stream until both directions are finished:

- When one side's TCP peer closes its sending direction (FIN), the stream direction is finished, and the other side shuts down the corresponding TCP sending direction. Half-closed connections are supported.
- After the header, the stream carries only payload bytes, without any framing.
- If the client accepts no further stream within 10 seconds, because it already forwards its `--max-connections`, the server closes the external connection.
- If the client can't connect to the destination within 10 seconds, it closes the stream, and the server closes the external connection.
- The server closes connections without data transfer in either direction for `--idle-timeout` seconds.

## Limits

The server limits the resources a single host can use.
Addresses are counted per IPv4 address and per IPv6 /64 network, because a single host often has a whole /64; IPv4-mapped IPv6 addresses count as IPv4.

| What                                                      | Default             | Server option              | When exceeded                                                        |
| --------------------------------------------------------- | ------------------- | -------------------------- | -------------------------------------------------------------------- |
| QUIC connections, including unauthenticated ones          | 64                  | `--max-quic-connections`   | New connections are refused.                                         |
| QUIC connections per address                              | 8                   |                            | New connections are refused.                                         |
| Failed handshakes or authentication attempts per address  | 5 within 10 minutes |                            | The address is blocked for 10 minutes: its connections are refused.  |
| Forwarded connections per client                          | 512                 | `--max-connections`        | New external connections wait in the listen backlog.                 |
| Forwarded connections per external address                | 64                  | `--max-connections-per-ip` | New external connections are closed right away.                      |
| Time without data transfer on a forwarded connection      | 600 s               | `--idle-timeout`           | The connection is closed.                                            |

Authentication timeouts count as failed attempts.
A successful authentication clears the address's failed attempts, unless it is blocked.
Refusing a QUIC connection happens before the TLS handshake and closes it with the QUIC transport error `CONNECTION_REFUSED`.

## Close codes

Both sides close the QUIC connection with one of these application error codes and a reason phrase for logs.

| Code | Meaning                                                                                   | Sent by | Client connects again |
| ---: | ----------------------------------------------------------------------------------------- | ------- | --------------------- |
|    0 | Normal end: shutdown of server or client, `BYE` or end of the control stream.             | both    | yes                   |
|    1 | Authentication failed: the peer did not prove that it knows the PSK.                      | both    | no                    |
|    2 | Authentication timed out.                                                                 | server  | yes                   |
|    3 | Protocol violation: a malformed listen port request or an unexpected control message.    | server  | no                    |
|    4 | Configuration timed out: no listen port request within 10 seconds.                        | server  | yes                   |
|    5 | Port not allowed by the server's `--allowed-client-ports`.                                | server  | no                    |
|    6 | Port unavailable: the server could not listen on the port, e.g. because it is in use.    | server  | yes                   |
|    7 | Keepalive failed.                                                                         | both    | yes                   |
|    8 | Internal error, e.g. a failure to send a message.                                         | both    | yes                   |

The client also exits instead of connecting again on TLS errors (e.g. an untrusted certificate or another protocol version) and invalid connection parameters.
Otherwise, it connects again with exponential backoff: after 1 second, doubling up to 60 seconds, each delay randomized to 50–100 % of its value.
After a connection worked for a minute, the delays start over.
