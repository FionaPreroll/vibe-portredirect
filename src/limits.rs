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

    /// Returns whether connections from `ip` are refused because of failed attempts.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.lock_failures()
            .get(&address_key(ip))
            .is_some_and(|record| record.is_blocked(now))
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
        let host = ip("192.0.2.1");

        admission.record_failure(host);
        admission.record_failure(host);
        assert!(!admission.is_blocked(host));

        admission.record_failure(host);
        assert!(admission.is_blocked(host));
        // Other addresses are not affected.
        assert!(!admission.is_blocked(ip("192.0.2.2")));

        // The block ends after its duration.
        tokio::time::advance(Duration::from_secs(299)).await;
        assert!(admission.is_blocked(host));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!admission.is_blocked(host));
    }

    #[tokio::test(start_paused = true)]
    async fn test_ipv6_network_is_blocked() {
        let admission = QuicAdmission::new(8, test_policy());
        for host in ["2001:db8::1", "2001:db8::2", "2001:db8::3"] {
            admission.record_failure(ip(host));
        }
        assert!(admission.is_blocked(ip("2001:db8::4")));
        assert!(!admission.is_blocked(ip("2001:db8:0:1::1")));
    }

    #[tokio::test(start_paused = true)]
    async fn test_failures_expire_after_window() {
        let admission = QuicAdmission::new(8, test_policy());
        let host = ip("192.0.2.1");

        admission.record_failure(host);
        admission.record_failure(host);
        tokio::time::advance(Duration::from_secs(61)).await;
        admission.record_failure(host);

        assert!(!admission.is_blocked(host));
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

        assert!(!admission.is_blocked(host));
    }

    #[tokio::test(start_paused = true)]
    async fn test_success_does_not_end_block() {
        let admission = QuicAdmission::new(8, test_policy());
        let host = ip("192.0.2.1");
        for _ in 0..3 {
            admission.record_failure(host);
        }

        admission.record_success(host);

        assert!(admission.is_blocked(host));
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
}
