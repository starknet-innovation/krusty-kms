use std::time::{SystemTime, UNIX_EPOCH};

/// Time source used by the gateway cache and operation bookkeeping.
pub trait Clock: Send + Sync {
    /// Current wall-clock time in milliseconds since Unix epoch.
    fn now_ms(&self) -> u64;
}

/// System clock implementation for production gateway usage.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_millis()
            .try_into()
            .expect("millisecond timestamp must fit into u64")
    }
}
