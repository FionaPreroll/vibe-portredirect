// PortRedirect - Link emulator for benchmarks
//
// Forwards UDP datagrams between a client and a server like a network link would: with a delay,
// random loss and optionally limited bandwidth, as `tc netem` does in the kernel. It needs no
// privileges, so benchmarks can run where netem isn't available. See docs/PERFORMANCE.md.
//
// The client sends to --listen, the emulator forwards to --upstream and the answers back to the
// address the client last sent from, so it serves one client at a time, e.g. one QUIC connection.
//
//     cargo run --release --example link_emulator -- \
//         --listen 127.0.0.1:4434 --upstream 127.0.0.1:4433 --rtt-ms 50 --loss-percent 1
//
// License: GPL-3.0-only

use clap::Parser;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};

#[derive(Parser, Debug)]
#[command(about = "Forwards UDP datagrams with delay, loss and limited bandwidth")]
struct Args {
    /// Address the client sends to.
    #[arg(long)]
    listen: SocketAddr,
    /// Address of the server.
    #[arg(long)]
    upstream: SocketAddr,
    /// Round-trip time to add, half in each direction, in milliseconds.
    #[arg(long, default_value_t = 0)]
    rtt_ms: u64,
    /// Share of the datagrams to drop in each direction, in percent.
    #[arg(long, default_value_t = 0.0)]
    loss_percent: f64,
    /// Bandwidth in each direction, in Mbit/s, 0 for no limit.
    #[arg(long, default_value_t = 0)]
    rate_mbit: u64,
    /// At the bandwidth limit, datagrams that would wait longer than this many milliseconds are
    /// dropped, like by a router with a full queue.
    #[arg(long, default_value_t = 50)]
    queue_ms: u64,
}

/// One direction of the link.
struct Link {
    delay: Duration,
    /// Probability that a datagram is dropped.
    loss: f64,
    /// Bandwidth in bytes per second, if limited.
    rate: Option<f64>,
    queue: Duration,
    /// When the link is free to send the next datagram, at the bandwidth limit.
    free_at: Instant,
    random: Random,
    forwarded: u64,
    dropped: u64,
}

impl Link {
    fn new(args: &Args, seed: u64) -> Self {
        Self {
            delay: Duration::from_millis(args.rtt_ms) / 2,
            loss: args.loss_percent / 100.0,
            rate: (args.rate_mbit > 0).then(|| args.rate_mbit as f64 * 1e6 / 8.0),
            queue: Duration::from_millis(args.queue_ms),
            free_at: Instant::now(),
            random: Random(seed | 1),
            forwarded: 0,
            dropped: 0,
        }
    }

    /// Returns when a datagram of `size` bytes, arriving now, leaves the link at the other end,
    /// or `None` if it is lost.
    fn admit(&mut self, size: usize, now: Instant) -> Option<Instant> {
        if self.random.unit() < self.loss {
            self.dropped += 1;
            return None;
        }
        let sent = match self.rate {
            None => now,
            Some(rate) => {
                let start = self.free_at.max(now);
                if start - now > self.queue {
                    self.dropped += 1;
                    return None;
                }
                self.free_at = start + Duration::from_secs_f64(size as f64 / rate);
                self.free_at
            }
        };
        self.forwarded += 1;
        Some(sent + self.delay)
    }
}

/// A small random number generator (xorshift64*).
struct Random(u64);

impl Random {
    /// Returns a number from 0 to 1, excluding 1.
    fn unit(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A datagram on its way, and when it arrives.
type InFlight = (Instant, Vec<u8>);

/// Receives datagrams on `socket`, passes them through `link`, and queues them for `queue`.
/// Datagrams from the client update `client`, the address to answer to.
async fn receive(
    socket: Arc<UdpSocket>,
    link: Arc<Mutex<Link>>,
    queue: mpsc::UnboundedSender<InFlight>,
    client: Option<Arc<Mutex<Option<SocketAddr>>>>,
) -> std::io::Result<()> {
    let mut buffer = vec![0u8; 65536];
    loop {
        let (length, from) = socket.recv_from(&mut buffer).await?;
        if let Some(client) = &client {
            *client.lock().unwrap() = Some(from);
        }
        let arrival = link.lock().unwrap().admit(length, Instant::now());
        if let Some(arrival) = arrival {
            let _ = queue.send((arrival, buffer[..length].to_vec()));
        }
    }
}

/// Sends the datagrams of `queue` from `socket` when they arrive, to `to` or to the client.
async fn deliver(
    socket: Arc<UdpSocket>,
    mut queue: mpsc::UnboundedReceiver<InFlight>,
    to: Arc<Mutex<Option<SocketAddr>>>,
) -> std::io::Result<()> {
    while let Some((arrival, datagram)) = queue.recv().await {
        sleep_until(arrival).await;
        let to = *to.lock().unwrap();
        if let Some(to) = to {
            // A full socket buffer drops the datagram, like a link would.
            let _ = socket.send_to(&datagram, to).await;
        }
    }
    Ok(())
}

/// Size of the sockets' buffers. The emulator itself mustn't drop datagrams when they arrive in
/// bursts, e.g. several at once from a sender that uses GSO.
const SOCKET_BUFFER: usize = 4 << 20;

/// Binds a UDP socket to `address`, with buffers of up to `SOCKET_BUFFER` bytes, as far as the
/// operating system allows (on Linux: `net.core.rmem_max` and `net.core.wmem_max`).
fn bind(address: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(address)?;
    let options = socket2::SockRef::from(&socket);
    // Smaller buffers only make drops likelier, they don't stop the emulator.
    let _ = options.set_recv_buffer_size(SOCKET_BUFFER);
    let _ = options.set_send_buffer_size(SOCKET_BUFFER);
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let to_server = Arc::new(Mutex::new(Link::new(&args, seed)));
    let to_client = Arc::new(Mutex::new(Link::new(&args, seed.rotate_left(32))));

    let client_side = Arc::new(bind(args.listen)?);
    let unspecified: SocketAddr = match args.upstream {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let server_side = Arc::new(bind(unspecified)?);
    let client = Arc::new(Mutex::new(None));
    let server = Arc::new(Mutex::new(Some(args.upstream)));
    eprintln!(
        "Forwarding {} <-> {}: RTT {} ms, loss {}%, bandwidth {}",
        args.listen,
        args.upstream,
        args.rtt_ms,
        args.loss_percent,
        match args.rate_mbit {
            0 => "unlimited".to_string(),
            rate => format!("{} Mbit/s, queue {} ms", rate, args.queue_ms),
        }
    );

    let (upstream_queue, upstream_in_flight) = mpsc::unbounded_channel();
    let (downstream_queue, downstream_in_flight) = mpsc::unbounded_channel();
    let from_client = tokio::spawn(receive(
        Arc::clone(&client_side),
        Arc::clone(&to_server),
        upstream_queue,
        Some(Arc::clone(&client)),
    ));
    let upstream = tokio::spawn(deliver(
        Arc::clone(&server_side),
        upstream_in_flight,
        server,
    ));
    let from_server = tokio::spawn(receive(
        Arc::clone(&server_side),
        Arc::clone(&to_client),
        downstream_queue,
        None,
    ));
    let downstream = tokio::spawn(deliver(client_side, downstream_in_flight, client));

    // Runs until interrupted, then prints how many datagrams were forwarded and dropped.
    let ended = tokio::select! {
        _ = tokio::signal::ctrl_c() => None,
        result = from_client => Some(result),
        result = upstream => Some(result),
        result = from_server => Some(result),
        result = downstream => Some(result),
    };
    if let Some(result) = ended {
        eprintln!("Forwarding failed: {:?}", result);
    }
    for (direction, link) in [("To the server", &to_server), ("To the client", &to_client)] {
        let link = link.lock().unwrap();
        eprintln!(
            "{}: {} datagrams forwarded, {} dropped",
            direction, link.forwarded, link.dropped
        );
    }
    Ok(())
}
