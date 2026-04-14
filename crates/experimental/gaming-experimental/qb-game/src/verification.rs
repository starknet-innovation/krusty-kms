//! Probabilistic verification for lie detection.
//!
//! Uses verifiable randomness to determine if a lie is caught.
//! The randomness is derived from both parties' commitments to ensure fairness.

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::commitment::PlayCommitment;
use crate::detection::{calculate_penalty, detection_probability};
use crate::payoff::get_yards;
use crate::types::{DefensiveCoverage, OffensivePlay, PlayResult};

/// Verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Was the lie detected?
    pub caught: bool,
    /// The random value used (0.0 - 1.0).
    pub random_value: f64,
    /// The detection threshold (0.0 - 1.0).
    pub detection_threshold: f64,
    /// Seed used for randomness (for auditability).
    pub seed: [u8; 32],
}

/// Generate verifiable randomness from both parties' commitments.
///
/// This ensures neither party can manipulate the detection outcome
/// since the randomness depends on both commitments.
pub fn generate_verifiable_randomness(
    offense_commitment: &PlayCommitment,
    defense_commitment: &PlayCommitment,
    play_number: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"QB_GAME_VERIFICATION");
    hasher.update(offense_commitment.hash);
    hasher.update(defense_commitment.hash);
    hasher.update(play_number.to_le_bytes());
    hasher.finalize().into()
}

/// Convert a 32-byte seed to a random value in [0.0, 1.0).
fn seed_to_random(seed: &[u8; 32]) -> f64 {
    // Use first 8 bytes as u64
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&seed[0..8]);
    let value = u64::from_le_bytes(bytes);

    // Convert to [0.0, 1.0)
    value as f64 / u64::MAX as f64
}

/// Perform probabilistic verification of a claim.
///
/// # Arguments
/// * `offense_commitment` - The offense's play commitment
/// * `defense_commitment` - The defense's coverage commitment
/// * `play_number` - Which play this is (for replay protection)
/// * `lie_magnitude` - How many yards above true the offense claimed
///
/// # Returns
/// Verification result indicating if the lie was caught.
pub fn verify_claim(
    offense_commitment: &PlayCommitment,
    defense_commitment: &PlayCommitment,
    play_number: u32,
    lie_magnitude: i32,
) -> VerificationResult {
    let seed = generate_verifiable_randomness(offense_commitment, defense_commitment, play_number);
    let random_value = seed_to_random(&seed);
    let detection_threshold = detection_probability(lie_magnitude);

    // If random value is below threshold, lie is caught
    let caught = lie_magnitude > 0 && random_value < detection_threshold;

    VerificationResult {
        caught,
        random_value,
        detection_threshold,
        seed,
    }
}

/// Perform a complete play resolution.
///
/// # Arguments
/// * `offense_play` - The offensive play that was run
/// * `defense_coverage` - The defensive coverage that was called
/// * `claimed_yards` - The yards the offense claims
/// * `play_number` - Which play this is
/// * `offense_commitment` - The offense's original commitment
/// * `defense_commitment` - The defense's original commitment
/// * `is_fourth_down` - Whether this is 4th down (affects penalties)
///
/// # Returns
/// Complete play result with all details.
pub fn resolve_play(
    offense_play: OffensivePlay,
    defense_coverage: DefensiveCoverage,
    claimed_yards: i32,
    play_number: u32,
    offense_commitment: &PlayCommitment,
    defense_commitment: &PlayCommitment,
    is_fourth_down: bool,
) -> PlayResult {
    let true_yards = get_yards(offense_play, defense_coverage);
    let lie_magnitude = claimed_yards - true_yards;

    // If not lying, no verification needed
    if lie_magnitude <= 0 {
        return PlayResult {
            offense_play,
            defense_coverage,
            true_yards,
            claimed_yards,
            lie_magnitude: 0,
            detection_probability: 0.0,
            was_caught: false,
            final_yards: claimed_yards,
            penalty: None,
        };
    }

    // Verify the claim
    let verification = verify_claim(
        offense_commitment,
        defense_commitment,
        play_number,
        lie_magnitude,
    );

    if verification.caught {
        let penalty = calculate_penalty(lie_magnitude, is_fourth_down);
        PlayResult {
            offense_play,
            defense_coverage,
            true_yards,
            claimed_yards,
            lie_magnitude,
            detection_probability: verification.detection_threshold,
            was_caught: true,
            final_yards: -(penalty.yard_loss),
            penalty: Some(penalty),
        }
    } else {
        PlayResult {
            offense_play,
            defense_coverage,
            true_yards,
            claimed_yards,
            lie_magnitude,
            detection_probability: verification.detection_threshold,
            was_caught: false,
            final_yards: claimed_yards,
            penalty: None,
        }
    }
}

/// Simulate a play with random detection (for testing/demo without commitments).
pub fn simulate_play(
    offense_play: OffensivePlay,
    defense_coverage: DefensiveCoverage,
    claimed_yards: i32,
    is_fourth_down: bool,
) -> PlayResult {
    let true_yards = get_yards(offense_play, defense_coverage);
    let lie_magnitude = claimed_yards - true_yards;

    // If not lying, no detection
    if lie_magnitude <= 0 {
        return PlayResult {
            offense_play,
            defense_coverage,
            true_yards,
            claimed_yards,
            lie_magnitude: 0,
            detection_probability: 0.0,
            was_caught: false,
            final_yards: claimed_yards,
            penalty: None,
        };
    }

    let detection_prob = detection_probability(lie_magnitude);
    let random_value: f64 = rand::rng().random();
    let was_caught = random_value < detection_prob;

    if was_caught {
        let penalty = calculate_penalty(lie_magnitude, is_fourth_down);
        PlayResult {
            offense_play,
            defense_coverage,
            true_yards,
            claimed_yards,
            lie_magnitude,
            detection_probability: detection_prob,
            was_caught: true,
            final_yards: -(penalty.yard_loss),
            penalty: Some(penalty),
        }
    } else {
        PlayResult {
            offense_play,
            defense_coverage,
            true_yards,
            claimed_yards,
            lie_magnitude,
            detection_probability: detection_prob,
            was_caught: false,
            final_yards: claimed_yards,
            penalty: None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{commit_defensive_coverage, commit_offensive_play};

    #[test]
    fn test_verifiable_randomness_deterministic() {
        let (c1, _) = commit_offensive_play(OffensivePlay::Slant);
        let (c2, _) = commit_defensive_coverage(DefensiveCoverage::Cover2);

        let r1 = generate_verifiable_randomness(&c1, &c2, 1);
        let r2 = generate_verifiable_randomness(&c1, &c2, 1);

        assert_eq!(r1, r2, "Same inputs should produce same randomness");
    }

    #[test]
    fn test_verifiable_randomness_varies_by_play() {
        let (c1, _) = commit_offensive_play(OffensivePlay::Slant);
        let (c2, _) = commit_defensive_coverage(DefensiveCoverage::Cover2);

        let r1 = generate_verifiable_randomness(&c1, &c2, 1);
        let r2 = generate_verifiable_randomness(&c1, &c2, 2);

        assert_ne!(
            r1, r2,
            "Different play numbers should produce different randomness"
        );
    }

    #[test]
    fn test_seed_to_random_range() {
        // Test various seeds
        for i in 0u8..100 {
            let mut seed = [i; 32];
            seed[1] = 255 - i;
            let r = seed_to_random(&seed);
            assert!((0.0..1.0).contains(&r), "Random value {} out of range", r);
        }
    }

    #[test]
    fn test_honest_claim_not_caught() {
        let (off_commit, _) = commit_offensive_play(OffensivePlay::Slant);
        let (def_commit, _) = commit_defensive_coverage(DefensiveCoverage::Cover2);

        let _true_yards = get_yards(OffensivePlay::Slant, DefensiveCoverage::Cover2);

        // Claim exact true yards
        let result = verify_claim(&off_commit, &def_commit, 1, 0);
        assert!(!result.caught, "Honest claim should never be caught");
        assert_eq!(result.detection_threshold, 0.0);
    }

    #[test]
    fn test_resolve_play_honest() {
        let (off_commit, _) = commit_offensive_play(OffensivePlay::Slant);
        let (def_commit, _) = commit_defensive_coverage(DefensiveCoverage::Cover2);

        let true_yards = get_yards(OffensivePlay::Slant, DefensiveCoverage::Cover2);

        let result = resolve_play(
            OffensivePlay::Slant,
            DefensiveCoverage::Cover2,
            true_yards, // Claim exact true yards
            1,
            &off_commit,
            &def_commit,
            false,
        );

        assert!(!result.was_caught);
        assert_eq!(result.final_yards, true_yards);
        assert!(result.penalty.is_none());
    }

    #[test]
    fn test_resolve_play_under_claim() {
        let (off_commit, _) = commit_offensive_play(OffensivePlay::Slant);
        let (def_commit, _) = commit_defensive_coverage(DefensiveCoverage::Cover2);

        let true_yards = get_yards(OffensivePlay::Slant, DefensiveCoverage::Cover2);

        // Under-claim (claim less than true)
        let result = resolve_play(
            OffensivePlay::Slant,
            DefensiveCoverage::Cover2,
            true_yards - 2,
            1,
            &off_commit,
            &def_commit,
            false,
        );

        assert!(!result.was_caught, "Under-claiming should never be caught");
        assert_eq!(result.final_yards, true_yards - 2);
    }

    #[test]
    fn test_simulate_play_basic() {
        let result = simulate_play(
            OffensivePlay::QbSneak,
            DefensiveCoverage::GoalLine,
            1, // Honest
            false,
        );

        assert_eq!(result.true_yards, 1);
        assert_eq!(result.final_yards, 1);
        assert!(!result.was_caught);
    }

    #[test]
    fn test_caught_penalty_applied() {
        // This test uses a specific seed that we know triggers detection
        let off_commit = PlayCommitment::from_bytes([0u8; 32]);
        let def_commit = PlayCommitment::from_bytes([1u8; 32]);

        // Run with a huge lie - very high detection probability
        // We'll run multiple times and ensure at least some get caught
        let mut caught_count = 0;
        let mut not_caught_count = 0;

        for play_num in 0..100 {
            let result = resolve_play(
                OffensivePlay::QbSneak,
                DefensiveCoverage::GoalLine,
                50, // Claim 50 yards on a 1 yard play (lie of 49!)
                play_num,
                &off_commit,
                &def_commit,
                false,
            );

            if result.was_caught {
                caught_count += 1;
                assert!(result.penalty.is_some());
                assert!(
                    result.final_yards < 0,
                    "Should have negative yards from penalty"
                );
            } else {
                not_caught_count += 1;
                assert!(result.penalty.is_none());
                assert_eq!(result.final_yards, 50);
            }
        }

        // With 95% detection probability, we should catch most
        assert!(
            caught_count > 80,
            "Should catch most big lies: caught {}/100",
            caught_count
        );
        // But we should also miss some (5% get away)
        assert!(
            not_caught_count > 0,
            "Should miss some big lies: not caught {}/100",
            not_caught_count
        );
    }

    #[test]
    fn test_fourth_down_turnover() {
        let result = simulate_play(
            OffensivePlay::HailMary,
            DefensiveCoverage::ManUnder,
            100,  // Absurd claim
            true, // 4th down
        );

        // If caught on 4th down, should be turnover
        if result.was_caught {
            let penalty = result.penalty.unwrap();
            assert!(penalty.turnover);
        }
    }
}
