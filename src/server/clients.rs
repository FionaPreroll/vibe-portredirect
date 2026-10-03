// PortRedirect Server - The clients the server accepts
//
// Each client has a name, one or two PSKs and the ports it may ask the server to listen on.
// Several clients may share ports: whoever connects first gets a port, and the others wait as
// standby until it is free again.
//
// License: GPL-3.0-only

use crate::protocol::auth::{ClientName, PskLookup, MAX_PSKS_PER_CLIENT};
use crate::server::PortSpec;

use anyhow::{bail, Result};
use secrecy::SecretString;
use std::collections::BTreeMap;
use std::fmt;
use tracing::info;

/// A client the server accepts.
#[derive(Clone, Debug)]
pub struct ClientEntry {
    pub name: ClientName,
    /// The client's PSK, or two while changing it.
    pub psks: Vec<SecretString>,
    /// The ports the client may ask the server to listen on.
    pub ports: Vec<PortSpec>,
}

/// The clients the server accepts, by name.
#[derive(Clone, Debug)]
pub struct ClientList(BTreeMap<ClientName, ClientEntry>);

impl ClientList {
    /// Returns a list with the only client of a server configured on the command line, named
    /// [`ClientName::DEFAULT`].
    pub fn single(psk: SecretString, ports: Vec<PortSpec>) -> Self {
        let client = ClientEntry {
            name: ClientName::default(),
            psks: vec![psk],
            ports,
        };
        Self(BTreeMap::from([(client.name.clone(), client)]))
    }

    /// Returns a list of `clients`.
    ///
    /// Fails if a name occurs twice, or a client has no PSK or more than
    /// [`MAX_PSKS_PER_CLIENT`]. Logs which ports several clients may use, so a standby setup is
    /// recognizable as such, see [`ClientList::shared_ports`].
    pub fn new(clients: impl IntoIterator<Item = ClientEntry>) -> Result<Self> {
        let mut list = BTreeMap::new();
        for client in clients {
            if !(1..=MAX_PSKS_PER_CLIENT).contains(&client.psks.len()) {
                bail!(
                    "client {:?} has {} PSKs, it needs one, or two while changing it",
                    client.name.as_str(),
                    client.psks.len()
                );
            }
            if let Some(duplicate) = list.insert(client.name.clone(), client) {
                bail!("client {:?} is listed twice", duplicate.name.as_str());
            }
        }
        let list = Self(list);
        for shared in list.shared_ports() {
            let ports = match shared.ports[..] {
                [(start, end)] if start == end => "port",
                _ => "ports",
            };
            info!(
                "Standby is active: clients {:?} and {:?} may both use {} {}. Whichever \
                 connects first gets a port, the other one waits until it is free.",
                shared.clients.0.as_str(),
                shared.clients.1.as_str(),
                ports,
                shared
            );
        }
        Ok(list)
    }

    /// Returns the client named `name`.
    pub fn get(&self, name: &ClientName) -> Option<&ClientEntry> {
        self.0.get(name)
    }

    /// Returns the names of the clients, in order.
    pub fn names(&self) -> impl Iterator<Item = &ClientName> {
        self.0.keys()
    }

    /// Returns the number of clients.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the ports each pair of clients may both use, for all pairs that share ports.
    pub fn shared_ports(&self) -> Vec<SharedPorts> {
        let clients: Vec<(&ClientName, Vec<(u16, u16)>)> = self
            .0
            .values()
            .map(|client| (&client.name, port_ranges(&client.ports)))
            .collect();
        let mut shared = Vec::new();
        for (index, (first, first_ports)) in clients.iter().enumerate() {
            for (second, second_ports) in &clients[index + 1..] {
                let ports = intersect(first_ports, second_ports);
                if !ports.is_empty() {
                    shared.push(SharedPorts {
                        clients: ((*first).clone(), (*second).clone()),
                        ports,
                    });
                }
            }
        }
        shared
    }
}

impl PskLookup for ClientList {
    fn psks(&self, name: &ClientName) -> Option<&[SecretString]> {
        self.get(name).map(|client| client.psks.as_slice())
    }
}

/// Ports two clients may both use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedPorts {
    pub clients: (ClientName, ClientName),
    /// Sorted, disjoint ranges of ports, including both ends.
    pub ports: Vec<(u16, u16)>,
}

impl fmt::Display for SharedPorts {
    /// Formats the ports like `--allowed-client-ports`, e.g. `443, 8000-8100`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ranges: Vec<String> = self
            .ports
            .iter()
            .map(|&(start, end)| {
                if start == end {
                    start.to_string()
                } else {
                    format!("{}-{}", start, end)
                }
            })
            .collect();
        f.write_str(&ranges.join(", "))
    }
}

/// Returns the ports `specs` allow as sorted, disjoint ranges. Port 0 is never allowed.
fn port_ranges(specs: &[PortSpec]) -> Vec<(u16, u16)> {
    let mut ranges: Vec<(u16, u16)> = specs
        .iter()
        .map(|spec| match *spec {
            PortSpec::Single(port) => (port, port),
            PortSpec::Range(start, end) => (start, end),
        })
        .map(|(start, end)| (start.max(1), end))
        .filter(|(start, end)| start <= end)
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(u16, u16)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if u32::from(start) <= u32::from(last.1) + 1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Returns the ports in both `a` and `b`, which are sorted, disjoint ranges.
fn intersect(a: &[(u16, u16)], b: &[(u16, u16)]) -> Vec<(u16, u16)> {
    let mut shared = Vec::new();
    for &(a_start, a_end) in a {
        for &(b_start, b_end) in b {
            let (start, end) = (a_start.max(b_start), a_end.min(b_end));
            if start <= end {
                shared.push((start, end));
            }
        }
    }
    shared.sort_unstable();
    shared
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::AllowedPorts;

    fn client(name: &str, psks: &[&str], ports: &str) -> ClientEntry {
        ClientEntry {
            name: name.parse().unwrap(),
            psks: psks.iter().map(|&psk| SecretString::from(psk)).collect(),
            ports: ports
                .split(',')
                .filter(|spec| !spec.is_empty())
                .map(|spec| spec.parse().unwrap())
                .collect(),
        }
    }

    fn name(name: &str) -> ClientName {
        name.parse().unwrap()
    }

    #[test]
    fn test_single_client() {
        let list = ClientList::single("secret".into(), vec![PortSpec::Single(443)]);
        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
        let client = list.get(&ClientName::default()).unwrap();
        assert!(client.ports.allows(443));
        assert_eq!(list.psks(&ClientName::default()).unwrap().len(), 1);
        assert!(list.psks(&name("other")).is_none());
    }

    #[test]
    fn test_clients_by_name() -> Result<()> {
        let list = ClientList::new([
            client("home", &["a"], "443"),
            client("office", &["b", "c"], "8000-8100"),
        ])?;
        assert_eq!(list.len(), 2);
        let names: Vec<&str> = list.names().map(ClientName::as_str).collect();
        assert_eq!(names, ["home", "office"]);
        assert!(list.get(&name("office")).unwrap().ports.allows(8050));
        assert_eq!(list.psks(&name("office")).unwrap().len(), 2);
        assert!(list.get(&name("lab")).is_none());
        assert!(list.shared_ports().is_empty());
        Ok(())
    }

    #[test]
    fn test_invalid_lists_are_rejected() {
        for (clients, expected) in [
            (
                vec![client("home", &["a"], "443"), client("home", &["b"], "80")],
                "client \"home\" is listed twice",
            ),
            (vec![client("home", &[], "443")], "has 0 PSKs"),
            (vec![client("home", &["a", "b", "c"], "443")], "has 3 PSKs"),
        ] {
            let err = ClientList::new(clients).unwrap_err();
            assert!(err.to_string().contains(expected), "{:#}", err);
        }
    }

    #[test]
    fn test_shared_ports() -> Result<()> {
        let list = ClientList::new([
            client("active", &["a"], "443,8000-8100"),
            client("standby", &["b"], "443,8050-8200,9000"),
            client("other", &["c"], "80,9000"),
        ])?;
        let shared = list.shared_ports();
        assert_eq!(
            shared,
            [
                SharedPorts {
                    clients: (name("active"), name("standby")),
                    ports: vec![(443, 443), (8050, 8100)],
                },
                SharedPorts {
                    clients: (name("other"), name("standby")),
                    ports: vec![(9000, 9000)],
                },
            ]
        );
        assert_eq!(shared[0].to_string(), "443, 8050-8100");
        Ok(())
    }

    #[test]
    fn test_port_ranges_are_merged() {
        let specs = [
            PortSpec::Range(10, 20),
            PortSpec::Single(21),
            PortSpec::Range(15, 18),
            PortSpec::Single(5),
            PortSpec::Range(0, 2),
            PortSpec::Single(0),
            PortSpec::Range(65535, 65535),
        ];
        assert_eq!(
            port_ranges(&specs),
            [(1, 2), (5, 5), (10, 21), (65535, 65535)]
        );
    }
}
