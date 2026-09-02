use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Time source used by the gateway cache and operation bookkeeping.
///
/// `now_ms` drives every TTL and stale-window decision, so an implementation
/// must never return less than it returned earlier: a backwards step shrinks
/// `now - generated_at` and revives entries that had already expired.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch, non-decreasing across calls.
    fn now_ms(&self) -> u64;
}

/// System clock implementation for production gateway usage.
///
/// Each reading is the maximum of three sources: the wall clock, a wall-clock
/// anchor advanced by the monotonic [`Instant`] clock, and the previous
/// reading. The anchor keeps time moving through backwards wall-clock steps
/// (NTP corrections, manual changes); the wall clock keeps it moving through
/// host suspension, where `Instant` may stand still; the previous reading
/// makes the sequence non-decreasing by construction.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        let anchor = ANCHOR.get_or_init(Anchor::capture);
        let anchored = anchored_now_ms(anchor.epoch_ms, anchor.started.elapsed());
        let wall = saturating_unix_time_ms(SystemTime::now());
        monotone_reading(&LAST_READING, anchored.max(wall))
    }
}

/// Wall-clock reading paired with the monotonic instant it was taken at.
struct Anchor {
    epoch_ms: u64,
    started: Instant,
}

impl Anchor {
    fn capture() -> Self {
        Self {
            epoch_ms: saturating_unix_time_ms(SystemTime::now()),
            started: Instant::now(),
        }
    }
}

/// Shared by every `SystemClock`: the type is a `Copy` unit struct for API
/// stability, so the anchor lives here and all instances report one timeline.
static ANCHOR: OnceLock<Anchor> = OnceLock::new();

/// Last value returned by any `SystemClock`; readings never fall below it.
static LAST_READING: AtomicU64 = AtomicU64::new(0);

/// Publish `candidate` as the newest reading unless an earlier reading was
/// already later, and return whichever is larger.
fn monotone_reading(last: &AtomicU64, candidate: u64) -> u64 {
    last.fetch_max(candidate, Ordering::AcqRel).max(candidate)
}

fn anchored_now_ms(epoch_ms: u64, elapsed: Duration) -> u64 {
    epoch_ms.saturating_add(saturating_duration_ms(elapsed))
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
    use super::{
        anchored_now_ms, monotone_reading, saturating_duration_ms, saturating_unix_time_ms, Clock,
        SystemClock,
    };
    use std::sync::atomic::AtomicU64;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    /// The property the snapshot cache relies on: successive readings never
    /// decrease, whatever the wall clock does in between.
    #[test]
    fn system_clock_never_decreases_across_calls() {
        let clock = SystemClock;
        let mut previous = clock.now_ms();
        for _ in 0..10_000 {
            let next = clock.now_ms();
            assert!(
                next >= previous,
                "clock went backwards: {previous} -> {next}"
            );
            previous = next;
        }
    }

    /// Anchoring must not detach the clock from Unix time: a fresh reading
    /// stays within a few seconds of the wall clock.
    #[test]
    fn system_clock_tracks_unix_time() {
        let wall_ms = i128::from(saturating_unix_time_ms(SystemTime::now()));
        let reading = i128::from(SystemClock.now_ms());
        assert!((reading - wall_ms).abs() < 5_000, "{reading} vs {wall_ms}");
    }

    #[test]
    fn anchored_time_is_monotone_in_elapsed_and_saturates() {
        let earlier = anchored_now_ms(1_000, Duration::from_millis(5));
        let later = anchored_now_ms(1_000, Duration::from_millis(6));
        assert!(earlier <= later);
        assert_eq!(anchored_now_ms(u64::MAX, Duration::from_secs(1)), u64::MAX);
    }

    /// Codex review: a forward wall-clock jump (e.g. resume from suspend, where
    /// `Instant` stood still) must be followed, and a backwards one ignored.
    #[test]
    fn readings_follow_forward_jumps_and_never_go_backwards() {
        let last = AtomicU64::new(0);
        assert_eq!(monotone_reading(&last, 1_000), 1_000);
        assert_eq!(
            monotone_reading(&last, 5_000),
            5_000,
            "forward jump followed"
        );
        assert_eq!(
            monotone_reading(&last, 2_000),
            5_000,
            "backwards step ignored"
        );
        assert_eq!(monotone_reading(&last, 5_001), 5_001);
    }
}
