// PortRedirect - Limits per network address
//
// License: GPL-3.0-only

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::time::Instant;
use tracing::warn;

/// Returns the key under which connections from `ip` are counted.
///
/// IPv6 addresses are grouped by their /64 prefix, as a single host typically controls a whole
/// /64 network. IPv4-mapped IPv6 addresses are treated as the IPv4 address they contain.
pub fn address_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let [a, b, c, d, ..] = v6.segments();
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
    }
}

/// Counts concurrent connections per network address (see [`address_key`]) and enforces a
/// maximum for each address.
#[derive(Clone, Debug)]
pub struct AddressConnectionLimit {
    /// Maximum number of connections per address, 0 for no limit.
    max_per_address: usize,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl AddressConnectionLimit {
    /// Creates a limit of `max_per_address` concurrent connections per address, 0 for no limit.
    pub fn new(max_per_address: usize) -> Self {
        Self {
            max_per_address,
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Registers a connection from `ip`, unless its address already has the maximum number of
    /// connections. The connection counts until the returned guard is dropped.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<AddressConnectionGuard> {
        let key = address_key(ip);
        let mut counts = self.lock();
        let count = counts.entry(key).or_insert(0);
        if self.max_per_address != 0 && *count >= self.max_per_address {
            return None;
        }
        *count += 1;
        Some(AddressConnectionGuard {
            counts: Arc::clone(&self.counts),
            key,
        })
    }

    /// Returns the number of connections currently registered for the address of `ip`.
    #[cfg(test)]
    pub fn count(&self, ip: IpAddr) -> usize {
        self.lock().get(&address_key(ip)).copied().unwrap_or(0)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<IpAddr, usize>> {
        // The map stays consistent even if a thread panicked while holding the lock.
        self.counts.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A connection registered with an [`AddressConnectionLimit`], unregistered on drop.
#[derive(Debug)]
pub struct AddressConnectionGuard {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    key: IpAddr,
}

impl Drop for AddressConnectionGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

/// Limits how fast new connections may come from each network address (see [`address_key`]).
///
/// Each address has a bucket of up to `burst` tokens, which refills at `rate` tokens per second,
/// and each connection takes a token. So an address may open `burst` connections at once, and
/// then `rate` per second.
#[derive(Debug)]
pub struct AddressRateLimit {
    /// Tokens per second, 0 for no limit.
    rate: u32,
    /// Size of each bucket.
    burst: u32,
    buckets: Mutex<Buckets>,
}

/// The buckets of an [`AddressRateLimit`].
#[derive(Debug)]
struct Buckets {
    by_address: HashMap<IpAddr, TokenBucket>,
    /// Number of addresses from which on full buckets are forgotten.
    next_cleanup: usize,
    last_cleanup: Instant,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    /// Adds the tokens gained since the last update, up to `burst`.
    fn refill(&mut self, now: Instant, rate: u32, burst: u32) {
        let gained = now.duration_since(self.updated).as_secs_f64() * f64::from(rate);
        self.tokens = (self.tokens + gained).min(f64::from(burst));
        self.updated = now;
    }
}

impl AddressRateLimit {
    /// Upper bound for the number of addresses tracked at a time, to bound memory use.
    const MAX_TRACKED_ADDRESSES: usize = 65536;

    /// Number of addresses up to which full buckets are kept.
    const MIN_CLEANUP: usize = 1024;

    /// Time between attempts to forget full buckets while tracking the maximum number of
    /// addresses, which costs time.
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

    /// Creates a limit of `rate` new connections per second and address, after `burst` at once.
    /// A rate of 0 means no limit.
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate,
            burst,
            buckets: Mutex::new(Buckets {
                by_address: HashMap::new(),
                next_cleanup: Self::MIN_CLEANUP,
                last_cleanup: Instant::now(),
            }),
        }
    }

    /// Takes a token for a new connection from `ip`. Returns false if its address has none left.
    pub fn try_take(&self, ip: IpAddr) -> bool {
        if self.rate == 0 {
            return true;
        }
        let now = Instant::now();
        let key = address_key(ip);
        let mut buckets = self.lock();
        if !buckets.by_address.contains_key(&key) && !self.make_room(&mut buckets, now) {
            // Too many addresses to track: let this one pass rather than use more memory.
            return true;
        }
        let bucket = buckets.by_address.entry(key).or_insert(TokenBucket {
            tokens: f64::from(self.burst),
            updated: now,
        });
        bucket.refill(now, self.rate, self.burst);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Makes room for another address by forgetting full buckets, which are like new ones, once
    /// enough addresses are tracked. Returns false if there is no room.
    fn make_room(&self, buckets: &mut Buckets, now: Instant) -> bool {
        let tracked = buckets.by_address.len();
        let at_maximum = tracked >= Self::MAX_TRACKED_ADDRESSES;
        let due = !at_maximum || now >= buckets.last_cleanup + Self::CLEANUP_INTERVAL;
        if tracked >= buckets.next_cleanup && due {
            let (rate, burst) = (self.rate, self.burst);
            buckets.by_address.retain(|_, bucket| {
                bucket.refill(now, rate, burst);
                bucket.tokens < f64::from(burst)
            });
            let remaining = buckets.by_address.len();
            buckets.next_cleanup =
                (2 * remaining).clamp(Self::MIN_CLEANUP, Self::MAX_TRACKED_ADDRESSES);
            buckets.last_cleanup = now;
        }
        buckets.by_address.len() < Self::MAX_TRACKED_ADDRESSES
    }

    /// Returns the number of addresses with a bucket.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.lock().by_address.len()
    }

    fn lock(&self) -> MutexGuard<'_, Buckets> {
        // The buckets stay consistent even if a thread panicked while holding the lock.
        self.buckets.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// When an address gets blocked after failed authentication attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockingPolicy {
    /// Number of failed attempts within `window` after which an address is blocked.
    pub max_failures: u32,
    /// Time in which failed attempts are counted.
    pub window: Duration,
    /// How long an address stays blocked.
    pub block_duration: Duration,
}

impl Default for BlockingPolicy {
    fn default() -> Self {
        Self {
            max_failures: 5,
            window: Duration::from_secs(600),
            block_duration: Duration::from_secs(600),
        }
    }
}

/// Admission control for the QUIC connections of a server.
///
/// It limits the concurrent connections per address and blocks addresses for a while after
/// repeated failed handshakes or authentication attempts, which limits online guessing of the PSK
/// and the load from a single host.
#[derive(Debug)]
pub struct QuicAdmission {
    connections: AddressConnectionLimit,
    policy: BlockingPolicy,
    failures: Mutex<HashMap<IpAddr, FailureRecord>>,
}

#[derive(Debug)]
struct FailureRecord {
    count: u32,
    window_start: Instant,
    blocked_until: Option<Instant>,
}

impl FailureRecord {
    fn is_blocked(&self, now: Instant) -> bool {
        self.blocked_until.is_some_and(|until| now < until)
    }

    fn is_relevant(&self, now: Instant, policy: &BlockingPolicy) -> bool {
        self.is_blocked(now) || now < self.window_start + policy.window
    }
}

impl QuicAdmission {
    /// Default maximum number of concurrent QUIC connections per address.
    pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 8;

    /// Upper bound for the number of addresses with recorded failures, to bound memory use.
    const MAX_TRACKED_ADDRESSES: usize = 65536;

    /// Creates the admission control with at most `max_connections_per_ip` concurrent
    /// connections per address (0 for no limit) and the given blocking policy.
    pub fn new(max_connections_per_ip: usize, policy: BlockingPolicy) -> Self {
        Self {
            connections: AddressConnectionLimit::new(max_connections_per_ip),
            policy,
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// Returns how much longer connections from `ip` are refused because of failed attempts,
    /// if they are.
    pub fn blocked_for(&self, ip: IpAddr) -> Option<Duration> {
        let now = Instant::now();
        self.lock_failures()
            .get(&address_key(ip))
            .and_then(|record| record.blocked_until)
            .filter(|&until| now < until)
            .map(|until| until - now)
    }

    /// Returns the maximum number of connections per address, 0 for no limit.
    pub fn max_connections_per_ip(&self) -> usize {
        self.connections.max_per_address
    }

    /// Registers a connection from `ip`, unless its address already has the maximum number of
    /// connections. The connection counts until the returned guard is dropped.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<AddressConnectionGuard> {
        self.connections.try_acquire(ip)
    }

    /// Records a failed handshake or authentication attempt from `ip`, which blocks the address
    /// once it reaches the policy's maximum.
    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let key = address_key(ip);
        let mut failures = self.lock_failures();

        if !failures.contains_key(&key) && failures.len() >= Self::MAX_TRACKED_ADDRESSES {
            failures.retain(|_, record| record.is_relevant(now, &self.policy));
            if failures.len() >= Self::MAX_TRACKED_ADDRESSES {
                // Too many addresses to track, give up on this one rather than using more memory.
                return;
            }
        }

        let record = failures.entry(key).or_insert(FailureRecord {
            count: 0,
            window_start: now,
            blocked_until: None,
        });
        if now >= record.window_start + self.policy.window {
            // Start a new window.
            record.count = 0;
            record.window_start = now;
        }
        record.count += 1;

        if record.count >= self.policy.max_failures && !record.is_blocked(now) {
            record.blocked_until = Some(now + self.policy.block_duration);
            record.count = 0;
            record.window_start = now;
            warn!(
                "Blocking {} for {:?} after {} failed handshakes or authentication attempts",
                key, self.policy.block_duration, self.policy.max_failures
            );
        }
    }

    /// Records a successful authentication from `ip`, which clears earlier failed attempts.
    pub fn record_success(&self, ip: IpAddr) {
        let key = address_key(ip);
        let mut failures = self.lock_failures();
        if failures
            .get(&key)
            .is_some_and(|record| !record.is_blocked(Instant::now()))
        {
            failures.remove(&key);
        }
    }

    fn lock_failures(&self) -> MutexGuard<'_, HashMap<IpAddr, FailureRecord>> {
        self.failures.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for QuicAdmission {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_MAX_CONNECTIONS_PER_IP,
            BlockingPolicy::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_address_key() {
        assert_eq!(address_key(ip("192.0.2.1")), ip("192.0.2.1"));
        assert_eq!(address_key(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
        assert_eq!(
            address_key(ip("2001:db8:1:2:3:4:5:6")),
            ip("2001:db8:1:2::")
        );
        assert_eq!(
            address_key(ip("2001:db8:1:2:ffff::1")),
            address_key(ip("2001:db8:1:2::2"))
        );
        assert_ne!(
            address_key(ip("2001:db8:1:2::1")),
            address_key(ip("2001:db8:1:3::1"))
        );
    }

    #[test]
    fn test_limit_per_address() {
        let limit = AddressConnectionLimit::new(2);
        let first = limit.try_acquire(ip("192.0.2.1")).unwrap();
        let _second = limit.try_acquire(ip("192.0.2.1")).unwrap();

        assert!(limit.try_acquire(ip("192.0.2.1")).is_none());
        assert_eq!(limit.count(ip("192.0.2.1")), 2);

        // Other addresses are counted separately.
        assert!(limit.try_acquire(ip("192.0.2.2")).is_some());

        // Dropping a guard frees its slot.
        drop(first);
        assert_eq!(limit.count(ip("192.0.2.1")), 1);
        assert!(limit.try_acquire(ip("192.0.2.1")).is_some());
    }

    #[test]
    fn test_ipv6_addresses_share_their_64_prefix() {
        let limit = AddressConnectionLimit::new(1);
        let _guard = limit.try_acquire(ip("2001:db8::1")).unwrap();
        assert!(limit.try_acquire(ip("2001:db8::2")).is_none());
        assert!(limit.try_acquire(ip("2001:db8:0:1::1")).is_some());
    }

    #[test]
    fn test_zero_means_unlimited() {
        let limit = AddressConnectionLimit::new(0);
        let guards: Vec<_> = (0..1000)
            .map(|_| limit.try_acquire(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap())
            .collect();
        assert_eq!(limit.count(IpAddr::V4(Ipv4Addr::LOCALHOST)), 1000);
        drop(guards);
        assert_eq!(limit.count(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0);
    }

    #[test]
    fn test_unused_addresses_are_removed() {
        let limit = AddressConnectionLimit::new(4);
        drop(limit.try_acquire(ip("192.0.2.1")).unwrap());
        assert!(limit.lock().is_empty());
    }

    fn test_policy() -> BlockingPolicy {
        BlockingPolicy {
            max_failures: 3,
            window: Duration::from_secs(60),
            block_duration: Duration::from_secs(300),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_blocking_after_failures() {
        let admission = QuicAdmission::new(8, test_policy());
        assert_eq!(admission.max_connections_per_ip(), 8);
        let host = ip("192.0.2.1");

        admission.record_failure(host);
        admission.record_failure(host);
        assert!(admission.blocked_for(host).is_none());

        admission.record_failure(host);
        assert_eq!(admission.blocked_for(host), Some(Duration::from_secs(300)));
        // Other addresses are not affected.
        assert!(admission.blocked_for(ip("192.0.2.2")).is_none());

        // The block ends after its duration.
        tokio::time::advance(Duration::from_secs(299)).await;
        assert_eq!(admission.blocked_for(host), Some(Duration::from_secs(1)));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(admission.blocked_for(host).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_ipv6_network_is_blocked() {
        let admission = QuicAdmission::new(8, test_policy());
        for host in ["2001:db8::1", "2001:db8::2", "2001:db8::3"] {
            admission.record_failure(ip(host));
        }
        assert!(admission.blocked_for(ip("2001:db8::4")).is_some());
        assert!(admission.blocked_for(ip("2001:db8:0:1::1")).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_failures_expire_after_window() {
        let admission = QuicAdmission::new(8, test_policy());
        let host = ip("192.0.2.1");

        admission.record_failure(host);
        admission.record_failure(host);
        tokio::time::advance(Duration::from_secs(61)).await;
        admission.record_failure(host);

        assert!(admission.blocked_for(host).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_success_clears_failures() {
        let admission = QuicAdmission::new(8, test_policy());
        let host = ip("192.0.2.1");

        admission.record_failure(host);
        admission.record_failure(host);
        admission.record_success(host);
        admission.record_failure(host);
        admission.record_failure(host);

        assert!(admission.blocked_for(host).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_success_does_not_end_block() {
        let admission = QuicAdmission::new(8, test_policy());
        let host = ip("192.0.2.1");
        for _ in 0..3 {
            admission.record_failure(host);
        }

        admission.record_success(host);

        assert!(admission.blocked_for(host).is_some());
    }

    #[test]
    fn test_connections_per_address() {
        let admission = QuicAdmission::new(2, test_policy());
        let _first = admission.try_acquire(ip("192.0.2.1")).unwrap();
        let _second = admission.try_acquire(ip("192.0.2.1")).unwrap();
        assert!(admission.try_acquire(ip("192.0.2.1")).is_none());
        assert!(admission.try_acquire(ip("192.0.2.2")).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn test_outdated_failures_are_pruned() {
        let admission = QuicAdmission::new(8, test_policy());
        for i in 0..QuicAdmission::MAX_TRACKED_ADDRESSES as u32 {
            admission.record_failure(IpAddr::V4(Ipv4Addr::from(i)));
        }
        assert_eq!(
            admission.lock_failures().len(),
            QuicAdmission::MAX_TRACKED_ADDRESSES
        );

        // While the failures are recent, new addresses are not tracked.
        admission.record_failure(ip("198.51.100.1"));
        assert!(!admission.lock_failures().contains_key(&ip("198.51.100.1")));

        // Outdated failures make room.
        tokio::time::advance(Duration::from_secs(61)).await;
        admission.record_failure(ip("198.51.100.1"));
        assert_eq!(admission.lock_failures().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limit_allows_a_burst_then_the_rate() {
        let limit = AddressRateLimit::new(2, 3);
        let host = ip("192.0.2.1");

        // A burst of 3 at once, then nothing until a token comes back.
        assert!((0..3).all(|_| limit.try_take(host)));
        assert!(!limit.try_take(host));
        tokio::time::advance(Duration::from_millis(400)).await;
        assert!(!limit.try_take(host));
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(limit.try_take(host));
        assert!(!limit.try_take(host));

        // After a pause, the bucket is full again, but not fuller.
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!((0..3).all(|_| limit.try_take(host)));
        assert!(!limit.try_take(host));
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limit_counts_per_address() {
        let limit = AddressRateLimit::new(1, 1);
        assert!(limit.try_take(ip("192.0.2.1")));
        assert!(!limit.try_take(ip("192.0.2.1")));
        // Another address has its own bucket, a host's /64 network shares one.
        assert!(limit.try_take(ip("192.0.2.2")));
        assert!(limit.try_take(ip("2001:db8:1:2::1")));
        assert!(!limit.try_take(ip("2001:db8:1:2::2")));
        assert!(limit.try_take(ip("2001:db8:1:3::1")));
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limit_zero_is_no_limit() {
        let limit = AddressRateLimit::new(0, 1);
        assert!((0..1000).all(|_| limit.try_take(ip("192.0.2.1"))));
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limit_forgets_full_buckets() {
        let limit = AddressRateLimit::new(10, 2);
        let address = |i: u32| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
        let kept = AddressRateLimit::MIN_CLEANUP as u32;
        for i in 0..kept {
            assert!(limit.try_take(address(i)));
        }
        assert_eq!(limit.tracked(), AddressRateLimit::MIN_CLEANUP);

        // Their buckets are full again, so the next new address makes the limit forget them.
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(limit.try_take(address(kept)));
        assert_eq!(limit.tracked(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limit_tracks_a_bounded_number_of_addresses() {
        let limit = AddressRateLimit::new(1, 1);
        let address = |i: u32| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
        let max = AddressRateLimit::MAX_TRACKED_ADDRESSES as u32;
        for i in 0..max {
            assert!(limit.try_take(address(i)));
        }

        // None of the buckets is full again, so further addresses aren't tracked, and pass.
        assert!(limit.try_take(address(max)));
        assert!(limit.try_take(address(max)));
        assert_eq!(limit.tracked(), AddressRateLimit::MAX_TRACKED_ADDRESSES);
        // A tracked address is still limited.
        assert!(!limit.try_take(address(0)));

        // Once the buckets are full again, the limit forgets them, at most once a second.
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(limit.try_take(address(max)));
        assert!(!limit.try_take(address(max)));
        assert_eq!(limit.tracked(), 1);
    }
}
