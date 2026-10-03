// PortRedirect Client - Reconnecting after failures
//
// License: GPL-3.0-only

use crate::protocol::auth::AuthenticationRejected;
use crate::protocol::close::CloseCode;

use quinn::{ConnectError, ConnectionError, TransportErrorCode};
use std::time::Duration;

/// Exponentially growing delays between reconnection attempts, with random jitter.
#[derive(Clone, Debug)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    /// Delays start at `initial` and double with each attempt, up to `max`.
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            next: initial,
        }
    }

    /// Returns the delay before the next attempt and doubles the following one.
    ///
    /// The delay is randomized between 50 % and 100 % of its nominal value, so that many clients
    /// don't reconnect in lockstep, e.g. after a server restart.
    pub fn next_delay(&mut self) -> Duration {
        let nominal = self.next;
        self.next = (self.next * 2).min(self.max);
        // Without randomness, use the nominal delay.
        let random = getrandom::u32().unwrap_or(u32::MAX);
        nominal.mul_f64(0.5 + 0.5 * f64::from(random) / f64::from(u32::MAX))
    }

    /// Starts over with the initial delay, e.g. after a connection worked for a while.
    pub fn reset(&mut self) {
        self.next = self.initial;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(60))
    }
}

/// Returns whether connecting again can't succeed without a change of the configuration, judging
/// by the error of a connection and the reason the connection was closed, if any.
///
/// Permanent are: the server's close codes for permanent problems (e.g. wrong PSK or port not
/// allowed), TLS errors (e.g. an untrusted certificate or another protocol version), a QUIC
/// version mismatch, invalid connection parameters and a rejected authentication.
pub fn is_permanent_error(error: &anyhow::Error, close_reason: Option<&ConnectionError>) -> bool {
    close_reason.is_some_and(is_permanent_connection_error)
        || error.chain().any(|cause| {
            cause.is::<AuthenticationRejected>()
                || cause
                    .downcast_ref::<ConnectionError>()
                    .is_some_and(is_permanent_connection_error)
                || cause
                    .downcast_ref::<ConnectError>()
                    .is_some_and(is_permanent_connect_error)
        })
}

fn is_permanent_connection_error(error: &ConnectionError) -> bool {
    match error {
        ConnectionError::ApplicationClosed(_) => {
            CloseCode::of(error).is_some_and(CloseCode::is_permanent)
        }
        ConnectionError::TransportError(transport_error) => is_tls_error(transport_error.code),
        ConnectionError::ConnectionClosed(close) => is_tls_error(close.error_code),
        ConnectionError::VersionMismatch => true,
        _ => false,
    }
}

fn is_permanent_connect_error(error: &ConnectError) -> bool {
    matches!(
        error,
        ConnectError::InvalidServerName(_)
            | ConnectError::InvalidRemoteAddress(_)
            | ConnectError::NoDefaultClientConfig
            | ConnectError::UnsupportedVersion
    )
}

/// Returns whether `code` carries a TLS alert, e.g. about an untrusted certificate or a missing
/// common application protocol (ALPN).
fn is_tls_error(code: TransportErrorCode) -> bool {
    (0x100..0x200).contains(&u64::from(code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use quinn::{ApplicationClose, ConnectionClose};

    fn closed_by_server(close_code: CloseCode) -> ConnectionError {
        ConnectionError::ApplicationClosed(ApplicationClose {
            error_code: close_code.code(),
            reason: Default::default(),
        })
    }

    #[test]
    fn test_backoff_doubles_up_to_max() {
        let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(10));
        let nominal = [1, 2, 4, 8, 10, 10];
        for seconds in nominal {
            let delay = backoff.next_delay();
            let nominal = Duration::from_secs(seconds);
            assert!(
                delay >= nominal / 2 && delay <= nominal,
                "{:?} not within jitter of {:?}",
                delay,
                nominal
            );
        }
    }

    #[test]
    fn test_backoff_reset() {
        let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(10));
        for _ in 0..5 {
            backoff.next_delay();
        }
        backoff.reset();
        assert!(backoff.next_delay() <= Duration::from_secs(1));
    }

    #[test]
    fn test_permanent_close_codes() {
        let error = anyhow!("connection ended");
        for close_code in [
            CloseCode::AuthenticationFailed,
            CloseCode::ProtocolViolation,
            CloseCode::PortNotAllowed,
        ] {
            assert!(is_permanent_error(
                &error,
                Some(&closed_by_server(close_code))
            ));
        }
        for close_code in [
            CloseCode::Ok,
            CloseCode::AuthenticationTimeout,
            CloseCode::ConfigurationTimeout,
            CloseCode::PortUnavailable,
            CloseCode::KeepaliveFailed,
            CloseCode::InternalError,
        ] {
            assert!(!is_permanent_error(
                &error,
                Some(&closed_by_server(close_code))
            ));
        }
    }

    #[test]
    fn test_permanent_error_in_chain() {
        let error = anyhow::Error::new(closed_by_server(CloseCode::PortNotAllowed))
            .context("server did not confirm the listen port");
        assert!(is_permanent_error(&error, None));

        let error = anyhow::Error::new(AuthenticationRejected("bad".into()))
            .context("failed to authenticate");
        assert!(is_permanent_error(&error, None));
    }

    #[test]
    fn test_tls_errors_are_permanent() {
        // E.g. the server rejects the client's protocol version (no_application_protocol).
        let error = ConnectionError::ConnectionClosed(ConnectionClose {
            error_code: TransportErrorCode::crypto(120),
            frame_type: None,
            reason: Default::default(),
        });
        assert!(is_permanent_error(
            &anyhow::Error::new(error).context("failed to connect"),
            None
        ));
    }

    #[test]
    fn test_network_errors_are_transient() {
        for error in [
            ConnectionError::TimedOut,
            ConnectionError::Reset,
            ConnectionError::LocallyClosed,
            // The server refuses connections while it is at its limit or the address is blocked.
            ConnectionError::ConnectionClosed(ConnectionClose {
                error_code: TransportErrorCode::CONNECTION_REFUSED,
                frame_type: None,
                reason: Default::default(),
            }),
        ] {
            assert!(!is_permanent_error(
                &anyhow::Error::new(error).context("failed to connect"),
                None
            ));
        }
        assert!(!is_permanent_error(&anyhow!("unknown error"), None));
    }

    #[test]
    fn test_invalid_server_name_is_permanent() {
        let error = anyhow::Error::new(ConnectError::InvalidServerName("-".into()));
        assert!(is_permanent_error(&error, None));
        let error = anyhow::Error::new(ConnectError::EndpointStopping);
        assert!(!is_permanent_error(&error, None));
    }
}
