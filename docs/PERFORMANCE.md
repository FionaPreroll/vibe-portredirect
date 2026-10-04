# Performance

How fast a tunnel is over links with delay and packet loss, how it was measured, and the values PortRedirect uses because of it ([#27](https://github.com/FionaPreroll/vibe-portredirect/issues/27)).

## Summary

- **Delay:** a single forwarded connection now reaches about 1 Gbit/s at 50 ms round-trip time and 390 Mbit/s at 150 ms, instead of 116 and 61 Mbit/s with quinn's defaults. QUIC's flow-control windows limited it to one window per round trip.
- **Bursts:** datagrams often arrive in bursts, and a full UDP socket buffer drops them, which QUIC takes for congestion. PortRedirect asks for 4 MiB buffers. On Linux, the operating system allows only 208 KiB by default, see [Recommendations](#recommendations): with that, ten connections at 50 ms reached 195 Mbit/s instead of 1.2 Gbit/s.
- **Loss:** with 1 % random loss, the default congestion controller, CUBIC, takes each loss for congestion and slows down to less than 4 Mbit/s at 50 ms and 150 ms, as TCP would. With `--congestion-control bbr` on both sides, the tunnel keeps 176 Mbit/s to 1.3 Gbit/s.
- **Authentication:** until a client has authenticated, the server lets it send only 64 KiB, see [SECURITY-REVIEW.md](SECURITY-REVIEW.md#5-before-authentication-a-client-can-fill-the-control-streams-receive-window).

## Results

Throughput through the tunnel in Mbit/s, from an iperf3 client via `portredirect_server`, the emulated link and `portredirect_client` to an iperf3 server: 0.7.0 with quinn's defaults, and now with CUBIC and with BBR on both sides.

| RTT | Loss | Connections | 0.7.0 | Now, CUBIC | Now, BBR |
|---:|---:|---:|---:|---:|---:|
| 0 ms | 0 % | 1 | 1721 | 1861 | 1758 |
| 0 ms | 0 % | 10 | 1690 | 2291 | 2213 |
| 0 ms | 1 % | 1 | 50 | 51 | 1212 |
| 0 ms | 1 % | 10 | 51 | 51 | 1285 |
| 50 ms | 0 % | 1 | 116 | 1028 | 1042 |
| 50 ms | 0 % | 10 | 189 | 1363 | 1393 |
| 50 ms | 1 % | 1 | 2.3 | 3.2 | 500 |
| 50 ms | 1 % | 10 | 2.2 | 2.5 | 1301 |
| 150 ms | 0 % | 1 | 61 | 388 | 391 |
| 150 ms | 0 % | 10 | 179 | 1327 | 1360 |
| 150 ms | 1 % | 1 | 0.9 | 0.9 | 176 |
| 150 ms | 1 % | 10 | 0.7 | below 1 | 732 |

- About 1.4 Gbit/s through the emulator, and 2.3 Gbit/s without it, are the limits of the machine, which runs all programs: from there on, more connections or larger windows don't help.
- Without loss, BBR is as fast as CUBIC. Data from the destination to the external client (iperf3's `-R`) gave the same results.
- With CUBIC, 150 ms and 1 % loss, ten connections were too slow for iperf3 to finish the test.

### What Limited the Throughput

Measured on the way, each with the values chosen before it:

| Change | 50 ms, 10 connections | 150 ms, 1 connection | 150 ms, 10 connections |
|---|---:|---:|---:|
| quinn's defaults | 189 | 61 | 179 |
| 4 MiB UDP socket buffers | 1215 | 63 | 515 |
| Stream window 4 MiB, connection and send window 16 MiB | 1298 | 202 | 749 |
| Stream window 8 MiB, connection and send window 32 MiB | 1379 | 389 | 1250 |
| Stream window 16 MiB, connection and send window 64 MiB | 1271 | 752 | 1267 |

- A connection sends at most one stream window per round trip: 1.25 MiB, quinn's default, allow 67 Mbit/s at 150 ms. All connections of a tunnel together send at most one send window per round trip: quinn's 10 MiB allow 533 Mbit/s at 150 ms.
- The copy buffer for each direction of a forwarded connection made little difference: 16, 64 and 256 KiB gave 1695, 1800 and 1944 Mbit/s for one connection without delay, and the same within 5 % for ten connections, and at 50 ms.

## Chosen Values

In `PortRedirectProtocol` (`src/lib.rs`), for both sides:

| Value | Size | Why |
|---|---:|---|
| Stream receive window | 8 MiB | One forwarded connection reaches about 1 Gbit/s at 50 ms and 400 Mbit/s at 150 ms. 16 MiB would double the latter, but also the memory a slow destination can make a side keep per connection. Linux's TCP allows up to 6 MiB per connection by default (`net.ipv4.tcp_rmem`). |
| Connection receive window | 32 MiB | Bounds the memory all streams of a tunnel can make the receiver keep, while four connections can each use a full stream window. |
| Send window | 32 MiB | Enough for the connection receive window at 150 ms, 1.7 Gbit/s. |
| Receive window before authentication | 64 KiB | The server's window until the client has authenticated: enough for the authentication. |
| UDP socket buffers | 4 MiB | Enough for bursts at more than 1 Gbit/s. The operating system may allow less, see [Recommendations](#recommendations). |
| Copy buffer | 64 KiB | Per direction of each forwarded connection. Larger buffers hardly help, and cost memory for each of up to 512 connections. |
| Congestion controller | CUBIC | quinn's default and its most tested one. BBR is far faster with random loss, but quinn marks it experimental, so it is an option: `--congestion-control bbr`. |

## Recommendations

- **Allow larger UDP buffers on Linux:** by default, Linux limits socket buffers to 208 KiB, and PortRedirect logs a hint when it gets less than it asks for. Allow 4 MiB on both machines, and make it permanent in `/etc/sysctl.d/`:

  ```sh
  sudo sysctl -w net.core.rmem_max=4194304 net.core.wmem_max=4194304
  ```

- **Lossy links:** on links that lose packets for other reasons than congestion, e.g. wireless or long-distance ones, use `--congestion-control bbr` on both the server and the client. Each side's option decides how fast it sends. Keep in mind that quinn marks its BBR implementation experimental, and that BBR can take more than its share of a bottleneck from CUBIC connections.
- **Prebuilt binaries:** use the default ones, for glibc. The `-musl` ones are linked statically, so they run on any distribution, but are a little slower where the CPU limits the throughput: over localhost, the x86_64 binary reached 11 to 15 % less than with glibc, with one and with ten connections. Over most real links, the link limits the throughput first.

## How It Was Measured

- **Machine:** 4 virtual CPUs, Linux 6.18, all programs on the same machine over localhost, release builds. `net.core.rmem_max` and `net.core.wmem_max` were 4 MiB, the 0.7.0 values used the default buffers.
- **Link:** `utils/link_emulator.rs` forwards the QUIC datagrams between client and server with half the round-trip time in each direction and drops each with the given probability, independently. It needs no privileges, unlike `tc netem`. It can also limit the bandwidth, which these measurements didn't. Its timers have a resolution of 1 ms, so it releases datagrams in bursts of up to 1 ms. Without delay and loss, the tunnel ran without it.
- **Traffic:** iperf3 for 12 seconds, the first 2 left out, with one and with ten parallel connections. Each value is a single run; repeated runs differed by up to about 10 %.

### Reproducing

Build the programs and the emulator, then run `utils/link_benchmark.py`, which starts everything for each case and prints a table like the ones above:

```sh
cargo build --release --bins --example link_emulator
utils/link_benchmark.py --rtt 0 50 150 --loss 0 1 --parallel 1 10
utils/link_benchmark.py --congestion-control bbr --rtt 50 --loss 1 --parallel 1
```

It needs iperf3. `--reverse` measures data from the destination to the external client, `--rate` limits the bandwidth in Mbit/s.
