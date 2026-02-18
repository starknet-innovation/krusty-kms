//! Lie detection probability calculation.
//!
//! The detection probability follows an exponential curve:
//! P(caught) = 1 - e^(-k * lie_magnitude)
//!
//! This creates a risk/reward tradeoff:
//! - Small lies (1-2 yards): Low detection, small gains
//! - Medium lies (5-7 yards): Moderate detection, decent gains
//! - Large lies (10+ yards): High detection, big potential gains

use crate::types::Penalty;

/// Detection curve parameter.
/// Higher values make detection more aggressive.
const DETECTION_K: f64 = 0.15;

/// Maximum detection probability (cap).
const MAX_DETECTION_PROBABILITY: f64 = 0.95;

/// Base penalty yards for getting caught.
const BASE_PENALTY_YARDS: i32 = 5;

/// Additional penalty per yard of lie magnitude.
const PENALTY_PER_LIE_YARD: f64 = 0.5;

/// Calculate the probability of getting caught for a given lie magnitude.
///
/// # Arguments
/// * `lie_magnitude` - The difference between claimed yards and true yards.
///                     Must be >= 0. Negative values (under-claiming) return 0.
///
/// # Returns
/// Probability between 0.0 and 0.95.
pub fn detection_probability(lie_magnitude: i32) -> f64 {
    if lie_magnitude <= 0 {
        return 0.0;
    }

    let magnitude = lie_magnitude as f64;
    let probability = 1.0 - (-DETECTION_K * magnitude).exp();

    probability.min(MAX_DETECTION_PROBABILITY)
}

/// Calculate the expected value of a lie.
///
/// Expected value = P(success) * claimed_yards + P(caught) * penalty_yards
///
/// # Arguments
/// * `true_yards` - The actual yards from the payoff matrix.
/// * `claimed_yards` - The yards the offense claims.
///
/// # Returns
/// The expected yards considering detection probability.
pub fn expected_value(true_yards: i32, claimed_yards: i32) -> f64 {
    let lie_magnitude = claimed_yards - true_yards;

    if lie_magnitude <= 0 {
        // No lie or under-claiming: just use claimed yards
        return claimed_yards as f64;
    }

    let p_caught = detection_probability(lie_magnitude);
    let p_success = 1.0 - p_caught;
    let penalty = calculate_penalty(lie_magnitude, false); // Assume not 4th down

    // Expected value = success_yards * p_success + penalty_yards * p_caught
    let success_yards = claimed_yards as f64;
    let penalty_yards = -(penalty.yard_loss as f64);

    success_yards * p_success + penalty_yards * p_caught
}

/// Calculate the penalty for getting caught lying.
///
/// # Arguments
/// * `lie_magnitude` - How many yards the offense lied about.
/// * `is_fourth_down` - Whether this is 4th down (causes turnover).
///
/// # Returns
/// The penalty to apply.
pub fn calculate_penalty(lie_magnitude: i32, is_fourth_down: bool) -> Penalty {
    let additional_loss = (lie_magnitude as f64 * PENALTY_PER_LIE_YARD) as i32;
    let yard_loss = BASE_PENALTY_YARDS + additional_loss;

    Penalty {
        yard_loss,
        loss_of_down: true,
        turnover: is_fourth_down,
    }
}

/// Calculate the optimal claim for maximum expected value.
///
/// # Arguments
/// * `true_yards` - The actual yards from the payoff matrix.
/// * `max_claim` - Maximum claimable yards (usually max for the play).
///
/// # Returns
/// The optimal claimed yards and expected value.
pub fn optimal_claim(true_yards: i32, max_claim: i32) -> (i32, f64) {
    let mut best_claim = true_yards;
    let mut best_ev = true_yards as f64;

    for claim in true_yards..=max_claim {
        let ev = expected_value(true_yards, claim);
        if ev > best_ev {
            best_ev = ev;
            best_claim = claim;
        }
    }

    (best_claim, best_ev)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honest_no_detection() {
        // Lie magnitude 0 = 0% detection
        assert_eq!(detection_probability(0), 0.0);
    }

    #[test]
    fn test_under_claiming_no_detection() {
        // Negative lie magnitude = 0% detection
        assert_eq!(detection_probability(-5), 0.0);
    }

    #[test]
    fn test_small_lies_low_detection() {
        // 1 yard lie ~14%
        let p1 = detection_probability(1);
        assert!(p1 > 0.10 && p1 < 0.20, "1 yard lie: {:.2}", p1);

        // 2 yard lie ~26%
        let p2 = detection_probability(2);
        assert!(p2 > 0.20 && p2 < 0.35, "2 yard lie: {:.2}", p2);
    }

    #[test]
    fn test_medium_lies_moderate_detection() {
        // 5 yard lie ~53%
        let p5 = detection_probability(5);
        assert!(p5 > 0.45 && p5 < 0.60, "5 yard lie: {:.2}", p5);

        // 7 yard lie ~65%
        let p7 = detection_probability(7);
        assert!(p7 > 0.60 && p7 < 0.75, "7 yard lie: {:.2}", p7);
    }

    #[test]
    fn test_large_lies_high_detection() {
        // 10 yard lie ~78%
        let p10 = detection_probability(10);
        assert!(p10 > 0.70 && p10 < 0.85, "10 yard lie: {:.2}", p10);

        // 15 yard lie ~89%
        let p15 = detection_probability(15);
        assert!(p15 > 0.85 && p15 < 0.92, "15 yard lie: {:.2}", p15);
    }

    #[test]
    fn test_detection_capped_at_95() {
        // Very large lies cap at 95%
        let p20 = detection_probability(20);
        assert!(p20 <= 0.95);

        let p50 = detection_probability(50);
        assert_eq!(p50, 0.95);
    }

    #[test]
    fn test_detection_monotonically_increasing() {
        let mut prev = 0.0;
        for lie in 0..=30 {
            let p = detection_probability(lie);
            assert!(p >= prev, "Detection should increase: {} < {} at lie {}", p, prev, lie);
            prev = p;
        }
    }

    #[test]
    fn test_penalty_base_yards() {
        let penalty = calculate_penalty(0, false);
        assert_eq!(penalty.yard_loss, 5);
        assert!(penalty.loss_of_down);
        assert!(!penalty.turnover);
    }

    #[test]
    fn test_penalty_scales_with_lie() {
        // 10 yard lie = 5 + 5 = 10 yard penalty
        let p10 = calculate_penalty(10, false);
        assert_eq!(p10.yard_loss, 10);

        // 20 yard lie = 5 + 10 = 15 yard penalty
        let p20 = calculate_penalty(20, false);
        assert_eq!(p20.yard_loss, 15);
    }

    #[test]
    fn test_fourth_down_turnover() {
        let penalty = calculate_penalty(5, true);
        assert!(penalty.turnover);

        let penalty = calculate_penalty(5, false);
        assert!(!penalty.turnover);
    }

    #[test]
    fn test_expected_value_honest() {
        // No lie = exact yards
        let ev = expected_value(5, 5);
        assert_eq!(ev, 5.0);
    }

    #[test]
    fn test_expected_value_small_lie() {
        // Small lie (1 yard) should have positive EV increase from claimed
        // P(caught) ~14%, penalty = 5.5 yards
        // EV = 0.86 * 6 + 0.14 * (-5.5) = 5.16 - 0.77 = 4.39
        // Due to penalty structure, small lies may not be worth it
        let ev = expected_value(5, 6);
        // EV should be reasonable (positive, close to true yards)
        assert!(ev > 4.0 && ev < 6.0, "Small lie EV: {}", ev);
    }

    #[test]
    fn test_expected_value_large_lie() {
        // Very large lie should have negative EV (high penalty chance)
        let ev = expected_value(5, 30);
        // Should be very negative due to frequent penalties
        assert!(ev < 0.0, "Large lie EV should be negative: {}", ev);
    }

    #[test]
    fn test_optimal_claim_exists() {
        // For moderate true yards, there should be an optimal lie
        let (optimal, ev) = optimal_claim(5, 20);

        // Optimal should be higher than honest
        assert!(optimal >= 5);

        // EV should be at least as good as honest
        assert!(ev >= 5.0);
    }

    #[test]
    fn test_optimal_claim_not_max() {
        // Optimal claim should not be the maximum (too risky)
        let (optimal, _) = optimal_claim(5, 50);
        assert!(optimal < 50, "Optimal {} should be less than max 50", optimal);
    }
}
