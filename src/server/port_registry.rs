// PortRedirect Server - Which client holds which listen port
//
// A client that connects again while the server still holds its port for an older connection,
// e.g. after the client restarted, replaces that connection right away. Another client has to
// wait until the port is free, e.g. a standby client.
//
// License: GPL-3.0-only

use crate::protocol::auth::ClientName;
use crate::protocol::close::CloseCode;

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::time::{timeout_at, Instant};
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Time to wait for a replaced connection to release its port.
pub const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

/// A connection that can hold a port and be replaced by a newer connection of the same client.
pub trait Replaceable: Clone + fmt::Debug + Send + Sync + 'static {
    /// Closes the connection because a newer one of the same client takes over its port.
    fn replace(&self);
}

impl Replaceable for quinn::Connection {
    fn replace(&self) {
        CloseCode::Replaced.close(self, "replaced by a new connection of the same client");
    }
}

/// The listen ports the server holds, by client.
#[derive(Debug)]
pub struct PortRegistry<C = quinn::Connection> {
    holders: Mutex<HashMap<u16, Holder<C>>>,
    next_id: AtomicU64,
}

#[derive(Debug)]
struct Holder<C> {
    client: ClientName,
    connection: C,
    id: u64,
    /// Cancelled when the port is released.
    released: CancellationToken,
}

/// Why a client can't have a port.
#[derive(Debug, PartialEq, Eq)]
pub enum PortTaken {
    /// Another client holds the port.
    ByOtherClient(ClientName),
    /// The replaced connection of the same client didn't release the port in time.
    NotReleased,
}

impl fmt::Display for PortTaken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortTaken::ByOtherClient(client) => {
                write!(f, "client {:?} holds the port", client.as_str())
            }
            PortTaken::NotReleased => write!(
                f,
                "the replaced connection didn't release the port within {:?}",
                RELEASE_TIMEOUT
            ),
        }
    }
}

impl std::error::Error for PortTaken {}

impl<C> Default for PortRegistry<C> {
    fn default() -> Self {
        Self {
            holders: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }
}

impl<C: Replaceable> PortRegistry<C> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes `port` for `connection` of `client`, until the returned lease is dropped.
    ///
    /// If an older connection of the same client holds the port, closes that connection with
    /// [`CloseCode::Replaced`] and waits up to [`RELEASE_TIMEOUT`] for it to release the port.
    pub async fn acquire(
        self: &Arc<Self>,
        port: u16,
        client: &ClientName,
        connection: &C,
    ) -> Result<PortLease<C>, PortTaken> {
        let deadline = Instant::now() + RELEASE_TIMEOUT;
        loop {
            let (replaced, released) = {
                let mut holders = self.lock();
                match holders.get(&port) {
                    None => {
                        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                        let released = CancellationToken::new();
                        holders.insert(
                            port,
                            Holder {
                                client: client.clone(),
                                connection: connection.clone(),
                                id,
                                released: released.clone(),
                            },
                        );
                        return Ok(PortLease {
                            registry: Arc::clone(self),
                            port,
                            id,
                            released,
                        });
                    }
                    Some(holder) if holder.client == *client => {
                        (holder.connection.clone(), holder.released.clone())
                    }
                    Some(holder) => return Err(PortTaken::ByOtherClient(holder.client.clone())),
                }
            };
            info!(
                "Replacing the older connection of client {:?} on port {}",
                client.as_str(),
                port
            );
            replaced.replace();
            if timeout_at(deadline, released.cancelled()).await.is_err() {
                return Err(PortTaken::NotReleased);
            }
        }
    }

    /// Returns the client that holds `port`, if any.
    pub fn holder(&self, port: u16) -> Option<ClientName> {
        self.lock().get(&port).map(|holder| holder.client.clone())
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u16, Holder<C>>> {
        // A panic while holding the lock leaves the map consistent.
        self.holders.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A client's hold on a listen port, see [`PortRegistry::acquire`]. Dropping it releases the port,
/// so drop it only after the TCP listener on the port is closed.
#[derive(Debug)]
pub struct PortLease<C: Replaceable = quinn::Connection> {
    registry: Arc<PortRegistry<C>>,
    port: u16,
    id: u64,
    released: CancellationToken,
}

impl<C: Replaceable> PortLease<C> {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl<C: Replaceable> Drop for PortLease<C> {
    fn drop(&mut self) {
        {
            let mut holders = self.registry.lock();
            if holders
                .get(&self.port)
                .is_some_and(|holder| holder.id == self.id)
            {
                holders.remove(&self.port);
            }
        }
        self.released.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::Notify;

    /// A connection that counts how often it was replaced.
    #[derive(Clone, Debug, Default)]
    struct TestConnection {
        replaced: Arc<Notify>,
        replace_count: Arc<AtomicUsize>,
    }

    impl Replaceable for TestConnection {
        fn replace(&self) {
            self.replace_count.fetch_add(1, Ordering::SeqCst);
            self.replaced.notify_one();
        }
    }

    fn name(name: &str) -> ClientName {
        name.parse().unwrap()
    }

    fn registry() -> Arc<PortRegistry<TestConnection>> {
        Arc::new(PortRegistry::new())
    }

    #[tokio::test]
    async fn test_dropping_the_lease_releases_the_port() {
        let registry = registry();
        let lease = registry
            .acquire(443, &name("home"), &TestConnection::default())
            .await
            .unwrap();
        assert_eq!(lease.port(), 443);
        assert_eq!(registry.holder(443), Some(name("home")));
        assert_eq!(registry.holder(80), None);

        drop(lease);
        assert_eq!(registry.holder(443), None);
    }

    #[tokio::test]
    async fn test_other_clients_have_to_wait() {
        let registry = registry();
        let active = TestConnection::default();
        let _lease = registry
            .acquire(443, &name("active"), &active)
            .await
            .unwrap();

        let result = registry
            .acquire(443, &name("standby"), &TestConnection::default())
            .await;

        assert_eq!(
            result.unwrap_err(),
            PortTaken::ByOtherClient(name("active"))
        );
        assert_eq!(active.replace_count.load(Ordering::SeqCst), 0);
        // Other ports are independent.
        registry
            .acquire(80, &name("standby"), &TestConnection::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_new_connection_of_the_same_client_replaces_the_old_one() {
        let registry = registry();
        let old = TestConnection::default();
        let old_lease = registry.acquire(443, &name("home"), &old).await.unwrap();

        let new = TestConnection::default();
        let acquiring = {
            let registry = Arc::clone(&registry);
            let new = new.clone();
            tokio::spawn(async move { registry.acquire(443, &name("home"), &new).await })
        };

        // The old connection is told to close, and releases the port when its listener is closed.
        old.replaced.notified().await;
        assert!(!acquiring.is_finished());
        drop(old_lease);

        let new_lease = acquiring.await.unwrap().unwrap();
        assert_eq!(registry.holder(443), Some(name("home")));
        assert_eq!(old.replace_count.load(Ordering::SeqCst), 1);
        assert_eq!(new.replace_count.load(Ordering::SeqCst), 0);
        drop(new_lease);
        assert_eq!(registry.holder(443), None);
    }

    #[tokio::test(start_paused = true)]
    async fn test_replaced_connection_that_keeps_the_port() {
        let registry = registry();
        let _old_lease = registry
            .acquire(443, &name("home"), &TestConnection::default())
            .await
            .unwrap();
        let start = Instant::now();

        let result = registry
            .acquire(443, &name("home"), &TestConnection::default())
            .await;

        assert_eq!(result.unwrap_err(), PortTaken::NotReleased);
        assert!(start.elapsed() >= RELEASE_TIMEOUT);
        assert!(PortTaken::NotReleased
            .to_string()
            .contains("didn't release"));
        assert_eq!(
            PortTaken::ByOtherClient(name("a")).to_string(),
            "client \"a\" holds the port"
        );
    }
}
