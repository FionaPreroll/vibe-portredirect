# PortRedirect Protocol (version 2)

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
2. The server opens the **control stream** and challenges the client to prove it knows the pre-shared key (PSK).
3. The client asks the server to listen on a TCP port; the server binds it and confirms.
4. For every external TCP connection the server accepts, it opens a **data stream** to the client, which connects to the destination and forwards bytes in both directions.
5. The client sends keepalive messages on the control stream for as long as the tunnel should exist.

## Transport

- QUIC with TLS 1.3, ALPN protocol identifier `pr-2`.
  The identifier changes with every incompatible protocol change; peers speaking a different version fail the TLS handshake ("peer doesn't support any known protocol").
  Version 1 (`pr-1`, e.g. `portredirect` 0.3.0 on crates.io) had no listen port negotiation.
- **Server authentication:** the server presents a certificate, by default a self-signed one it generates on first start (`cert.der`, `key.der` in its configuration directory).
  The client trusts exactly the certificate in its own `cert.der` (copied from the server) and verifies that it is issued for `--quic-remote-hostname-match`, or for the IP address of `--quic-remote-host` if not given.
- **Client authentication:** none at the TLS level; the client proves knowledge of the PSK on the control stream, see below.
- **Streams:** only the server opens streams, all of them bidirectional.
  The server allows the client to open zero streams, so a client cannot send anything except on streams the server opened.
- **Address validation:** the server answers new connections with a stateless retry, so a client must be able to receive packets at its source address before the server keeps state for it.
- Further transport settings of the server: QUIC keep-alive packets every 25 s, idle timeout 30 s (Quinn default), spin bit disabled, round-robin stream scheduling.

## Control stream

The first stream of a connection is opened by the server and stays open for the connection's lifetime.
Messages are ASCII text or fixed-size binary records, as shown below (`\n` is a line feed, `uN` an N-bit unsigned integer in network byte order).

If the server rejects anything, it closes the whole QUIC connection with application error code 0 and a reason starting with `ERR`, see [Connection close reasons](#connection-close-reasons).

### 1. Authentication

Server to client, at most 256 bytes:

```text
WHO THE HECK ARE YOU?\n
this-is-the-challenge-<random>-at-<minutes>-pr-v1\n
```

- `<random>`: 32 bytes from the operating system's secure random number generator, hex encoded (64 characters).
- `<minutes>`: minutes since the Unix epoch on the server. It is informational only; the server does not check it, replay protection comes from the random part.

Client to server, exactly 129 bytes:

```text
<response>\n
```

- `<response>`: SHA-512 of the challenge line (without the line feed) immediately followed by the PSK bytes, hex encoded in lower case (128 characters).

Server to client:

- `HAPPY\n` if the response matches; continue with step 2.
- `BAD\n` otherwise, and the server closes the connection with `ERR failed authentication`.

The server closes the connection with `ERR authentication timed out` if authentication is not finished within 10 seconds.

### 2. Listen port

Client to server, 12 bytes:

```text
LISTENPORT <port: u16>
```

(no space; the literal `LISTENPORT` is followed directly by two bytes)

The server checks the port against its `--allowed-client-ports`, binds a TCP listener on `--local-host` and that port, and answers with 11 bytes:

```text
LISTENING <bound port: u16>
```

(again without a space)

From now on, the server accepts external TCP connections on that port for this client.
Errors close the connection: `ERR port not allowed`, `ERR failed binding tcp listener` (e.g. the port is in use, also by a previous connection of the same client that has not timed out yet), `ERR failed configuration` (malformed request), `ERR configuration timed out` (no request within 10 seconds).

### 3. Keepalive

| Message     | Direction        | Meaning                                                   |
| ----------- | ---------------- | --------------------------------------------------------- |
| `PING\n`    | client to server | Sent right away and then every 30 seconds.                |
| `PONG\n`    | server to client | Answer to each `PING`.                                    |
| `BYE\n`     | client to server | Ends the connection. Not sent by the current client.      |

- The client stops its keepalive loop if a `PONG` does not arrive within 30 seconds, or anything else arrives instead.
- The server ends the connection if it receives no message for 60 seconds, an unexpected message, or `BYE`.
  It then stops the TCP listener and closes the connection with `OK normal shutdown`.

## Data streams

For each external TCP connection the server accepts, it opens a new bidirectional stream.
The client connects to its destination (`--destination-host`, `--destination-port`) and both sides copy bytes between the TCP connection and the stream until both directions are finished:

- When one side's TCP peer closes its sending direction (FIN), the stream direction is finished, and the other side shuts down the corresponding TCP sending direction. Half-closed connections are supported.
- The stream carries only payload bytes; there is no framing or metadata such as the external client's address.
- The client accepts at most 100 concurrent data streams (Quinn default). Further external connections wait until a stream is closed.

## Connection close reasons

| Reason                                 | Cause                                                  |
| -------------------------------------- | ------------------------------------------------------ |
| `ERR failed authentication`            | Wrong PSK or malformed response.                       |
| `ERR authentication timed out`         | No valid response within 10 seconds.                   |
| `ERR failed configuration`             | Malformed listen port request.                         |
| `ERR configuration timed out`          | No listen port request within 10 seconds.              |
| `ERR port not allowed`                 | Port is not in the server's `--allowed-client-ports`.  |
| `ERR failed binding tcp listener`      | The server could not listen on the port.               |
| `ERR failed confirming configuration`  | Sending `LISTENING` failed.                            |
| `OK normal shutdown`                   | Keepalive ended, see above.                            |

All of them use application error code 0.
