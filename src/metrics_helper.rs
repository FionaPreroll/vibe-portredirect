/// A simple trait to abstract a counter metric.
pub trait MetricsCounter {
    /// Increment the counter by a given amount.
    fn inc_by(&self, amount: u64);
}
use std::sync::atomic::{AtomicU64, Ordering};

/// A dummy counter for testing purposes or cases where we want to read the result directly.
#[derive(Default)]
pub struct DummyCounter(AtomicU64);

impl DummyCounter {
    pub fn new() -> Self {
        DummyCounter(AtomicU64::new(0))
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl MetricsCounter for DummyCounter {
    fn inc_by(&self, amount: u64) {
        self.0.fetch_add(amount, Ordering::Relaxed);
    }
}

