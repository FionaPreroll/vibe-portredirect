// PortRedirect Protocol Module - Application error codes for closing connections
//
// License: GPL-3.0-only

use quinn::{ConnectionError, VarInt};

/// Application error codes a peer closes a QUIC connection with.
///
/// The codes tell the other side why the connection ended, in particular whether connecting
/// again can succeed without a configuration change (see [`CloseCode::is_permanent`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseCode {
    /// The tunnel ended normally.
    Ok = 0,
    /// The peer failed to prove that it knows the PSK.
    AuthenticationFailed = 1,
    /// The client did not authenticate in time.
    AuthenticationTimeout = 2,
    /// The peer sent a malformed or unexpected message.
    ProtocolViolation = 3,
    /// The client did not request a listen port in time.
    ConfigurationTimeout = 4,
    /// The requested listen port is not allowed by the server.
    PortNotAllowed = 5,
    /// The server could not listen on the requested port, e.g. because it is in use.
    PortUnavailable = 6,
    /// The keepalive failed.
    KeepaliveFailed = 7,
    /// An unexpected error, e.g. an I/O error.
    InternalError = 8,
    /// A new connection of the same client took over the listen port.
    Replaced = 9,
    /// The peer lacks a feature this side requires.
    Unsupported = 10,
}

impl CloseCode {
    const ALL: [CloseCode; 11] = [
        CloseCode::Ok,
        CloseCode::AuthenticationFailed,
        CloseCode::AuthenticationTimeout,
        CloseCode::ProtocolViolation,
        CloseCode::ConfigurationTimeout,
        CloseCode::PortNotAllowed,
        CloseCode::PortUnavailable,
        CloseCode::KeepaliveFailed,
        CloseCode::InternalError,
        CloseCode::Replaced,
        CloseCode::Unsupported,
    ];

    /// Returns the close code with the numeric value `code`, if it is known.
    pub fn from_code(code: VarInt) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|close_code| close_code.code() == code)
    }

    /// Returns the close code of a connection the peer closed with one of our codes.
    pub fn of(error: &ConnectionError) -> Option<Self> {
        match error {
            ConnectionError::ApplicationClosed(close) => Self::from_code(close.error_code),
            _ => None,
        }
    }

    /// Returns the numeric value sent over the wire.
    pub fn code(self) -> VarInt {
        VarInt::from(self as u32)
    }

    /// Returns whether the client should not connect again: connecting again would fail the same
    /// way until the configuration of client or server changes, or, after
    /// [`CloseCode::Replaced`], take the port from another instance of the same client.
    pub fn is_permanent(self) -> bool {
        matches!(
            self,
            CloseCode::AuthenticationFailed
                | CloseCode::ProtocolViolation
                | CloseCode::PortNotAllowed
                | CloseCode::Replaced
                | CloseCode::Unsupported
        )
    }

    /// Closes `connection` with this code and a human-readable `reason`.
    pub fn close(self, connection: &quinn::Connection, reason: &str) {
        connection.close(self.code(), reason.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codes_round_trip() {
        for close_code in CloseCode::ALL {
            assert_eq!(CloseCode::from_code(close_code.code()), Some(close_code));
        }
        assert_eq!(CloseCode::from_code(VarInt::from(1000u32)), None);
    }

    #[test]
    fn test_codes_are_stable() {
        // The values are part of the protocol, see docs/PROTOCOL.md.
        let values: Vec<u64> = CloseCode::ALL
            .iter()
            .map(|c| c.code().into_inner())
            .collect();
        assert_eq!(values, (0..11).collect::<Vec<u64>>());
    }

    #[test]
    fn test_permanent_codes() {
        let permanent: Vec<CloseCode> = CloseCode::ALL
            .into_iter()
            .filter(|c| c.is_permanent())
            .collect();
        assert_eq!(
            permanent,
            [
                CloseCode::AuthenticationFailed,
                CloseCode::ProtocolViolation,
                CloseCode::PortNotAllowed,
                CloseCode::Replaced,
                CloseCode::Unsupported
            ]
        );
    }
}
