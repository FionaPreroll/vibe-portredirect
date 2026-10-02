// PortRedirect Protocol Module
//
// License: GPL-3.0-only

use anyhow::{anyhow, Result};
use std::time::{SystemTime, UNIX_EPOCH};

/// Trait to abstract over time-related functionality.
pub trait TimeProvider {
    /// Returns the current time as a SystemTime.
    fn now(&self) -> SystemTime;
}

/// Default system time provider.
pub struct SystemTimeProvider;

impl TimeProvider for SystemTimeProvider {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Extension trait to compute elapsed minutes since UNIX epoch.
pub trait ElapsedMinutes {
    fn elapsed_minutes(&self) -> u64;
}

impl ElapsedMinutes for SystemTime {
    fn elapsed_minutes(&self) -> u64 {
        self.duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / 60)
            .unwrap_or(0)
    }
}

/// Generate securely random bytes (you might want to inject an RNG in tests).
pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("failed to get random bytes: {}", e))?;
    Ok(buf)
}
