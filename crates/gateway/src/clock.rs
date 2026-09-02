use std::sync::{Mutex, PoisonError};
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
/// Readings advance along a monotonic timeline anchored to the wall clock. A
/// wall-clock reading ahead of the timeline (a forward step, or a resume from
/// suspension during which [`Instant`] stood still) re-anchors the timeline
/// there, so readings keep advancing from the new high-water mark; a reading
/// behind it (a backwards step) is ignored and the timeline keeps advancing on
/// its own. Readings therefore never decrease and never freeze.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        // Sample both clocks while holding the lock: readings are then ordered
        // exactly like the lock acquisitions, so a caller that sampled earlier
        // but locked later cannot publish an older reading than its predecessor.
        let mut anchor = ANCHOR.lock().unwrap_or_else(PoisonError::into_inner);
        let wall_ms = saturating_unix_time_ms(SystemTime::now());
        let now = Instant::now();
        advance(&mut anchor, wall_ms, now)
    }
}

/// Wall-clock reading paired with the monotonic instant it was taken at.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    epoch_ms: u64,
    started: Instant,
}

/// Shared by every `SystemClock`: the type is a `Copy` unit struct for API
/// stability, so the timeline lives here and all instances report one clock.
static ANCHOR: Mutex<Option<Anchor>> = Mutex::new(None);

/// One clock step. Returns the reading and re-anchors when the wall clock is
/// ahead of the timeline; a wall clock behind it leaves the anchor untouched.
fn advance(anchor: &mut Option<Anchor>, wall_ms: u64, now: Instant) -> u64 {
    let anchored = anchor.map(|a| {
        a.epoch_ms.saturating_add(saturating_duration_ms(
            now.saturating_duration_since(a.started),
        ))
    });
    match anchored {
        Some(anchored) if anchored >= wall_ms => anchored,
        _ => {
            *anchor = Some(Anchor {
                epoch_ms: wall_ms,
                started: now,
            });
            wall_ms
        }
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
    use super::{advance, saturating_duration_ms, saturating_unix_time_ms, Clock, SystemClock};
    use std::time::Instant;
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

    /// Codex review: forward jumps are followed (re-anchored), backwards steps
    /// are ignored, and after a forward jump that is later corrected the clock
    /// keeps advancing instead of freezing at the high-water mark.
    #[test]
    fn advance_follows_forward_jumps_ignores_backward_steps_and_never_freezes() {
        let t0 = Instant::now();
        let mut anchor = None;
        assert_eq!(advance(&mut anchor, 1_000, t0), 1_000);
        // Wall clock stepped back by 500 ms while 100 ms elapsed: keep advancing.
        assert_eq!(
            advance(&mut anchor, 500, t0 + Duration::from_millis(100)),
            1_100
        );
        // Wall clock jumps far ahead (resume from suspend): follow it.
        assert_eq!(
            advance(&mut anchor, 9_000, t0 + Duration::from_millis(200)),
            9_000
        );
        // The jump is corrected backwards: readings continue from 9_000 + elapsed.
        assert_eq!(
            advance(&mut anchor, 1_300, t0 + Duration::from_millis(300)),
            9_100
        );
        assert_eq!(
            advance(&mut anchor, 1_400, t0 + Duration::from_millis(400)),
            9_200
        );
    }

    #[test]
    fn advance_saturates_at_u64_max() {
        let t0 = Instant::now();
        let mut anchor = None;
        assert_eq!(advance(&mut anchor, u64::MAX, t0), u64::MAX);
        assert_eq!(
            advance(&mut anchor, 0, t0 + Duration::from_secs(1)),
            u64::MAX
        );
    }
}
