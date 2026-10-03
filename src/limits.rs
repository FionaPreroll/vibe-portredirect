// PortRedirect - Limits per network address
//
// License: GPL-3.0-only

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};

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
}
