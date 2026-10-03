# PortRedirect Protocol (version 5)

This document describes how `portredirect_client` and `portredirect_server` talk to each other.
It reflects the implementation in `src/protocol/` and `src/quic/`; if they disagree, the code wins and this document needs fixing.

## Overview

```text
 external TCP client          portredirect_server              portredirect_client          destination
        |                            |   <== QUIC connection ==    |                            |
        |                            |   control stream: auth,     |                            |
        |                            |   HELLO/WELCOME, keepalive  |                            |
        |-- TCP connect ------------>|                             |                            |
        |                            |-- open data stream -------->|-- TCP connect ------------>|
        |<=========== bytes =========|=========== bytes ===========|=========== bytes =========>|
```

1. The client connects to the server via QUIC and verifies the server's certificate.
2. The server opens the **control stream**. The client names itself, and client and server prove to each other that they know the client's pre-shared key (PSK).
3. The client asks the server to listen on a TCP port (`HELLO`); the server binds it and confirms (`WELCOME`).
4. For every external TCP connection the server accepts, it opens a **data stream** to the client and names the external client in a header. The client connects to the destination and forwards bytes in both directions.
5. The client sends keepalive messages on the control stream for as long as the tunnel should exist.
6. A side that ends the connection closes it with a [close code](#close-codes) that tells why. The client connects again, unless the code means that connecting again would fail the same way.

## Versions and compatibility

Each incompatible version of the protocol has its own ALPN identifier, see [Transport](#transport):

| Version | ALPN   | PortRedirect | Changes                                                                                                       |
| ------: | ------ | ------------ | ------------------------------------------------------------------------------------------------------------- |
|       5 | `pr-5` | 0.7.0        | Messages with type and length, parameters, client names, aborted data streams, `DRAIN`.                       |
|       4 | `pr-4` | 0.6.0        | Header at the start of each data stream, so protocols in which the server speaks first, e.g. SMTP, work.     |
|       3 | `pr-3` | 0.5.0        | Mutual authentication bound to the TLS session, close codes.                                                  |
|       2 | `pr-2` | 0.4.0        | Listen port negotiation; only the client authenticated, without binding the proof to the TLS session.        |
|       1 | `pr-1` | 0.3.0        | No listen port negotiation.                                                                                   |

Version 5 is designed to stay compatible:

- PortRedirect 1.x will speak version 5, and every 1.x client will work with every 1.x server, whichever is newer.
  Until 1.0 is released, every incompatible change still gets a new identifier.
- New optional features are negotiated as [extensions](#extensions). Receivers skip [parameters](#parameters) they don't know, treat unknown [close codes](#close-codes) like code 8 (connect again) and unknown [stream error codes](#aborted-connections) like code 1 (aborted).
- An incompatible change requires PortRedirect 2.0 and a new identifier. A 2.x server will also speak version 5 and handle each connection according to the version the TLS handshake chose, so the server can be updated first and its clients later.

## Transport

- QUIC with TLS 1.3, ALPN protocol identifier `pr-5`.
  Peers speaking a different version, or offering none, fail the TLS handshake ("peer doesn't support any known protocol").
- **Server authentication:** the server presents a certificate, by default a self-signed one it generates on first start (`cert.der`, `key.der` in its configuration directory).
  The client trusts exactly the certificate in its own `cert.der` (copied from the server) and verifies that it is issued for `--quic-remote-hostname-match`, or for the IP address of `--quic-remote-host` if not given.
  In addition, the server proves on the control stream that it knows the client's PSK.
- **Client authentication:** none at the TLS level; the client names itself and proves on the control stream that it knows its PSK, see below.
- **Streams:** only the server opens streams, all of them bidirectional.
  The server allows the client to open zero streams, so a client cannot send anything except on streams the server opened.
  The client accepts one stream more than its `--max-connections`, for the control stream.
- **Address validation:** the server answers new connections with a stateless retry, so a client must be able to receive packets at its source address before the server keeps state for it.
- **Admission control:** the server refuses connections beyond its [limits](#limits), and from addresses that failed to authenticate repeatedly, before the TLS handshake.
- Further transport settings: both sides send QUIC keep-alive packets every 25 s, the idle timeout is 30 s (Quinn default), the spin bit is disabled; the server schedules its streams round-robin.

## Control stream

The first stream of a connection is opened by the server and stays open for the connection's lifetime.
In the formats below, `uN` is an N-bit unsigned integer in network byte order, `[N]` are N raw bytes, and literals like `CHALLENGE` are ASCII without spaces or terminators.

If a side rejects anything, it closes the whole QUIC connection with a [close code](#close-codes).

### 1. Authentication

The server knows a list of clients, each with a **name**, one or two PSKs (two while changing it) and the ports it may use.
A server configured on the command line has a single client named `default`, with the PSK and `--allowed-client-ports` given there; clients name themselves `default` unless configured otherwise (`--client-name`).
Names consist of 1 to 64 letters, digits, dots, underscores or hyphens (`A-Z a-z 0-9 . _ -`), so they can safely appear in logs.

Both sides prove that they know the client's PSK, with proofs that are bound to the TLS session and to the client's name.

**Session binding:** both sides export 32 bytes of keying material from the TLS session ([RFC 8446, section 7.5](https://www.rfc-editor.org/rfc/rfc8446#section-7.5)), with the label `EXPORTER-portredirect-v5-authentication` and an empty context.
The value is the same on both ends of a connection and unique to it, so a proof is worthless in any other connection, e.g. when replayed or relayed.

**Proofs** are HMAC-SHA256 tags (32 bytes), keyed with the bytes of the PSK, over an ASCII label, the session binding, the nonce and the client's name with its length:

```text
client proof = HMAC-SHA256(PSK, "portredirect v5 client proof" || binding || nonce || name length: u8 || name)
server proof = HMAC-SHA256(PSK, "portredirect v5 server proof" || binding || nonce || name length: u8 || name)
```

(`||` is concatenation.) The labels differ, so a client proof can't serve as server proof or vice versa.

**Messages:**

1. Server to client, 41 bytes:

   ```text
   CHALLENGE <nonce: [32]>
   ```

   `<nonce>` are 32 bytes from the operating system's secure random number generator.

2. Client to server:

   ```text
   RESPONSE <name length: u8> <name: [name length]> <client proof: [32]>
   ```

   The server checks the proof with the PSKs of the named client.
   If the server has no client with that name, or the proof is wrong, it closes the connection with code 1 without sending anything else.
   Both cases look the same from outside and take the same time: the server always checks two PSKs, with random ones in place of missing ones. So its answers don't reveal which names exist.

3. Server to client, 40 bytes:

   ```text
   ACCEPTED <server proof: [32]>
   ```

   The server proves its knowledge with the PSK the client's proof was made with.
   If the proof is wrong, the client closes the connection with code 1.

Both sides verify proofs in constant time.
The client proves its knowledge first: anyone can connect to the server, but only a server with the certificate's private key gets a client's proof, so nobody else can use one to guess the PSK offline.
The name travels inside TLS, so only that server learns it.
The server closes the connection with code 2 if authentication is not finished within 10 seconds.

**Example:** with the PSK `test-psk`, the name `home`, the binding bytes `0x00`, `0x01`, …, `0x1f` and the nonce bytes `0x20`, `0x21`, …, `0x3f`, the proofs are:

```text
client proof: 0a777ecbe15f463d8b64ee83b80f3b7dadd0dc762903faec5a1c7614293ac91b
server proof: d82322ef17b0e7218b0213953921bac78fd87347ddab8a36806c3bc786450008
```

### 2. Messages

After the authentication, each message on the control stream has this format:

```text
<type: u8> <length: u16> <payload: [length]>
```

The payload has at most 1024 bytes.

| Type | Name      | Direction        | Payload                     | Meaning                                                                                     |
| ---: | --------- | ---------------- | --------------------------- | ------------------------------------------------------------------------------------------- |
|    1 | `HELLO`   | client to server | [parameters](#parameters)   | Right after the authentication: the port the server should listen on, see [3](#3-setting-up-the-tunnel). |
|    2 | `WELCOME` | server to client | [parameters](#parameters)   | Answer to `HELLO` once the server listens on the port.                                     |
|    3 | `PING`    | client to server | empty                       | Keepalive, see [4](#4-keepalive-and-drain).                                                 |
|    4 | `PONG`    | server to client | empty                       | Answer to each `PING`.                                                                      |
|    5 | `DRAIN`   | either           | empty                       | The sender starts no new forwarded connections, running ones may finish.                    |

An unknown type or a longer payload is a protocol violation (code 3).
A side sends new message types only after the other side announced the [extension](#extensions) they belong to.
Receivers ignore a payload of `PING`, `PONG` and `DRAIN`.

#### Parameters

`HELLO`, `WELCOME` and the [header of data streams](#data-streams) consist of parameters:

```text
<id: u16> <length: u16> <value: [length]>
```

Senders order parameters by ID, each ID occurs at most once.
Receivers skip parameters with unknown IDs; a missing required parameter, an ID that occurs twice, a truncated parameter or an invalid value is a protocol violation.

| ID         | Name          | In                    | Value                                                                                          |
| ---------- | ------------- | --------------------- | ---------------------------------------------------------------------------------------------- |
| 1          | `software`    | `HELLO`, `WELCOME`    | The sender's software and version as UTF-8, at most 64 bytes, e.g. `portredirect_client 0.7.0`. Optional, only for logs. |
| 2          | `listen_port` | `HELLO`, `WELCOME`    | u16: the port the server should listen on (`HELLO`), or listens on (`WELCOME`). Required.    |
| 3          | `peer`        | data stream header    | The external client's address: `<family: u8>` (4 or 6), `<address: [4] or [16]>`, `<port: u16>`. IPv4-mapped IPv6 addresses are sent as IPv4. Required. |
| from 0x100 | extensions    | `HELLO`, `WELCOME`    | See [Extensions](#extensions).                                                                  |

### 3. Setting up the tunnel

The client sends `HELLO` with the port it wants within 10 seconds after the authentication.
For example, `HELLO` for port 443:

```text
01 00 23                                       type 1 (HELLO), 35 bytes of parameters
00 01 00 19 "portredirect_client 1.0.0"        software
00 02 00 02 01 bb                              listen_port 443
```

The server then:

1. Checks the port against the ports of the client that authenticated. Port 0 is never allowed, the system would choose a random port.
2. Takes the port for this connection:
   - If an older connection of the **same client** holds the port, e.g. because the client restarted while the server still kept its old connection, the server closes the older connection with code 9 and waits up to 5 seconds until it released the port.
   - If **another client** holds the port, the port is unavailable (code 6). That client may be configured to use the same port, e.g. as standby: it gets the port once it is free.
3. Binds a TCP listener on `--local-host` and the port, and answers with `WELCOME`, containing the bound port.

From now on, the server accepts external TCP connections on that port for this client.
On errors, the server closes the connection: with code 5 if the client may not use the port, 6 if it is unavailable (another client holds it, or the server could not listen on it, e.g. because another program uses it), 3 for a malformed `HELLO` or another message instead of it, and 4 if no `HELLO` arrives within 10 seconds.

### 4. Keepalive and DRAIN

- The client sends `PING` right away and then every 30 seconds, and the server answers each with `PONG`.
- The client closes the connection with code 7 if a `PONG` does not arrive within 30 seconds, and with code 3 if a message other than `PONG` or `DRAIN` arrives.
- The server ends the connection if it receives no message for 60 seconds (code 7), a message other than `PING` or `DRAIN` (code 3), or the end of the control stream (code 0).
  It then stops the TCP listener and closes the connection.
- **`DRAIN`** announces that the sender starts no new forwarded connections, while running ones may finish:
  - From the client, it makes the server stop the TCP listener and release the port, so another connection, e.g. a new instance of the same client, can take it without replacing the draining connection. The tunnel stays up for the running connections until the client closes the connection.
  - From the server, it tells the client that no new connections will come, e.g. because the server shuts down.

  PortRedirect 0.7.0 understands `DRAIN`, but doesn't send it yet.

### 5. Extensions

A later 1.x version adds optional features as extensions, each with a parameter ID from 0x100:

- The client includes the parameter in `HELLO` if it supports the extension; the server includes it in `WELCOME` if it supports and enables it. Only then do both sides use it.
- A side that requires an extension the other side lacks, e.g. because it is configured to use it, closes the connection with code 10.

Version 5 defines no extensions yet.

## Data streams

For each external TCP connection the server accepts, it opens a new bidirectional stream and starts it with a header, server to client:

```text
<length: u16> <parameters: [length]>
```

The header has at most 1024 bytes of [parameters](#parameters) and contains the `peer` parameter, e.g. for `192.0.2.1:50000`:

```text
00 0b 00 03 00 07 04 c0 00 02 01 c3 50
```

QUIC announces a new stream to the peer only with its first data. So the header also makes the client learn about the connection right away, even if the external client waits for the destination to speak first, as in SMTP.
The client logs the external client's address (at debug level), but doesn't pass it on to the destination.

Then the client connects to its destination (`--destination-host`, `--destination-port`), and both sides copy bytes between the TCP connection and the stream until both directions are finished:

- When one side's TCP peer closes its sending direction normally (FIN), the stream direction is finished, and the other side shuts down the corresponding TCP sending direction. Half-closed connections are supported.
- After the header, the stream carries only payload bytes, without any framing.
- The server closes connections without data transfer in either direction for `--idle-timeout` seconds, normally (FIN).

### Aborted connections

A side that aborts a data stream resets its sending direction (`RESET_STREAM`) and stops its receiving direction (`STOP_SENDING`) with one of these error codes:

| Code | Name             | Meaning                                                                                              |
| ---: | ---------------- | ---------------------------------------------------------------------------------------------------- |
|    0 | ok               | Normal end, e.g. after the idle timeout. Quinn stops a stream with code 0 when it is dropped before its end. |
|    1 | aborted          | The sender's TCP connection was reset or failed, or the sender aborted the stream for another reason, e.g. an invalid header. |
|    2 | connect failed   | The client could not connect to the destination: refused, unreachable, or not within 10 seconds.   |

Unknown codes other than 0 count as 1.

A side that receives code 1 or 2 resets its TCP connection (RST) instead of closing it normally, so truncated transfers don't look complete:

| Event                                                     | Result                                                                                          |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| The external client resets its connection.                | The server aborts the stream with code 1, the client resets its connection to the destination. |
| The destination resets its connection.                    | The client aborts the stream with code 1, the server resets the external connection.           |
| The client can't connect to the destination.             | The client aborts the stream with code 2, the server resets the external connection. A "connection refused" is impossible, because the server already accepted the connection; a reset comes closest. |
| The client accepts no further stream within 10 seconds, because it already forwards its `--max-connections`. | The server resets the external connection. |
| The QUIC connection ends while connections are forwarded, e.g. because it was lost, timed out or replaced. | Both sides reset their TCP connections, because the transfers are incomplete. |

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

Authentication timeouts count as failed attempts, and so do unknown client names.
A successful authentication clears the address's failed attempts, unless it is blocked.
Refusing a QUIC connection happens before the TLS handshake and closes it with the QUIC transport error `CONNECTION_REFUSED`.

## Close codes

Both sides close the QUIC connection with one of these application error codes and a reason phrase for logs.

| Code | Meaning                                                                                   | Sent by | Client connects again |
| ---: | ----------------------------------------------------------------------------------------- | ------- | --------------------- |
|    0 | Normal end: shutdown of server or client, or end of the control stream.                   | both    | yes                   |
|    1 | Authentication failed: the peer did not prove that it knows the PSK, or the server has no client with that name. | both    | no                    |
|    2 | Authentication timed out.                                                                 | server  | yes                   |
|    3 | Protocol violation: a malformed or unexpected message.                                    | both    | no                    |
|    4 | Configuration timed out: no `HELLO` within 10 seconds.                                    | server  | yes                   |
|    5 | Port not allowed for this client.                                                         | server  | no                    |
|    6 | Port unavailable: another client holds it, or the server could not listen on it, e.g. because another program uses it. | server  | yes                   |
|    7 | Keepalive failed.                                                                         | both    | yes                   |
|    8 | Internal error, e.g. a failure to send a message.                                        | both    | yes                   |
|    9 | Replaced: a new connection of the same client took over the port.                         | server  | no                    |
|   10 | Unsupported: the peer lacks an [extension](#extensions) this side requires.               | both    | no                    |

Clients treat unknown codes like code 8.
A client whose connection is replaced (code 9) doesn't connect again: two running instances with the same name would otherwise take the port from each other in turns.

The client also exits instead of connecting again on TLS errors (e.g. an untrusted certificate or another protocol version) and invalid connection parameters.
Otherwise, it connects again with exponential backoff: after 1 second, doubling up to 60 seconds, each delay randomized to 50–100 % of its value.
After a connection worked for a minute, the delays start over.
