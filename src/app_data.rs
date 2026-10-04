// PortRedirect
//
// License: GPL-3.0-only

use secrecy::SecretString;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::host_port::HostPort;
use crate::protocol::auth::ClientName;
use crate::server::clients::ClientList;
use crate::server::port_registry::PortRegistry;
use crate::server::ForwardingLimits;

// Storage for application data for handler functions.
#[derive(Clone, Debug)]
pub struct ServerAppData {
    /// The clients the server accepts, with their PSKs and ports.
    pub clients: ClientList,

    // IP to bind to the TCP listener to
    pub local_bind_ip: String,

    // Limits for the connections forwarded for each client.
    pub forwarding_limits: ForwardingLimits,

    /// Which client holds which listen port.
    pub ports: Arc<PortRegistry>,
}

impl ServerAppData {
    /// Returns the data of a server with a single client, named [`ClientName::DEFAULT`], which
    /// authenticates with `connection_auth_psk` and may use `local_bind_ports`.
    #[cfg(test)]
    pub fn new(
        connection_auth_psk: SecretString,
        local_bind_ip: String,
        local_bind_ports: Vec<crate::server::PortSpec>,
    ) -> Self {
        Self::with_clients(
            ClientList::single(connection_auth_psk, local_bind_ports),
            local_bind_ip,
        )
    }

    /// Returns the data of a server that accepts `clients`.
    pub fn with_clients(clients: ClientList, local_bind_ip: String) -> Self {
        ServerAppData {
            clients,
            local_bind_ip,
            forwarding_limits: ForwardingLimits::default(),
            ports: Arc::new(PortRegistry::new()),
        }
    }

    /// Replaces the default limits for the connections forwarded for each client.
    pub fn with_forwarding_limits(mut self, forwarding_limits: ForwardingLimits) -> Self {
        self.forwarding_limits = forwarding_limits;
        self
    }
}

// Implementing the Display trait for ServerAppData.
impl fmt::Display for ServerAppData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServerAppData {{ clients: {}, PSKs: [REDACTED], local_bind_ip: {} }}",
            self.clients.len(),
            self.local_bind_ip
        )
    }
}

// Storage for application data for handler functions.
#[derive(Clone, Debug)]
pub struct ClientAppData {
    pub connection: Arc<Mutex<Option<quinn::Connection>>>,
    /// The name the client authenticates with.
    pub client_name: ClientName,
    pub connection_auth_psk: SecretString,

    /// Where to forward connections to. A name is looked up for each connection.
    pub forward_destination: HostPort,

    // TCP port the server should listen on for external connections.
    pub remote_listen_port: u16,
}

impl ClientAppData {
    /// Returns the data of a client named [`ClientName::DEFAULT`], see
    /// [`ClientAppData::with_client_name`].
    pub fn new(
        connection_auth_psk: SecretString,
        forward_destination: impl Into<HostPort>,
        remote_listen_port: u16,
    ) -> Self {
        ClientAppData {
            connection: Arc::new(Mutex::new(None)),
            client_name: ClientName::default(),
            connection_auth_psk,

            forward_destination: forward_destination.into(),
            remote_listen_port,
        }
    }

    /// Replaces the name the client authenticates with.
    pub fn with_client_name(mut self, client_name: ClientName) -> Self {
        self.client_name = client_name;
        self
    }
}

// Implementing the Display trait for ClientAppData.
impl fmt::Display for ClientAppData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientAppData {{ connection: {:?}, client_name: {}, connection_auth_psk: [REDACTED], destination: {}, remote_listen_port: {} }}", self.connection, self.client_name, self.forward_destination, self.remote_listen_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_hides_the_psk() {
        let server = ServerAppData::new("server-secret".into(), "0.0.0.0".into(), Vec::new());
        let client =
            ClientAppData::new("client-secret".into(), HostPort::new("127.0.0.1", 80), 443)
                .with_client_name("home".parse().unwrap());

        let (server, client) = (server.to_string(), client.to_string());

        assert!(
            server.contains("clients: 1") && !server.contains("server-secret"),
            "{}",
            server
        );
        assert!(
            client.contains("client_name: home") && !client.contains("client-secret"),
            "{}",
            client
        );
    }
}
