use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        saturating_unix_time_ms(SystemTime::now())
    }
}

fn saturating_unix_time_ms(now: SystemTime) -> u64 {
    match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => saturating_duration_ms(duration),
        Err(_) => 0,
    }
}

fn saturating_duration_ms(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    if millis > u128::from(u64::MAX) {
        u64::MAX
    } else {
        millis as u64
    }
}

#[cfg(test)]
mod tests {
    use super::{saturating_duration_ms, saturating_unix_time_ms};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn system_clock_saturates_before_unix_epoch_to_zero() {
        let before_epoch = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(saturating_unix_time_ms(before_epoch), 0);
    }

    #[test]
    fn duration_millis_saturates_to_u64_max() {
        let overflowing = Duration::from_secs(u64::MAX);
        assert_eq!(saturating_duration_ms(overflowing), u64::MAX);
    }
}
