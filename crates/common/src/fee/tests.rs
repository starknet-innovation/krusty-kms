//! Unit tests for [`super::FeeBounds`] resolution and its ceiling.

use super::*;

/// ~0.0000002 STRK all in.
fn cheap_estimate() -> FeeEstimateInput {
    FeeEstimateInput {
        l1_gas_consumed: 100,
        l1_gas_price: 1_000,
        l2_gas_consumed: 100_000,
        l2_gas_price: 1_000,
        l1_data_gas_consumed: 100,
        l1_data_gas_price: 1_000,
    }
}

/// Every gas field pinned, so no estimate is consulted.
fn explicit_bounds(l1: u64, l1p: u128, l2: u64, l2p: u128) -> FeeBounds {
    FeeBounds {
        l1_gas: Some(l1),
        l1_gas_price: Some(l1p),
        l2_gas: Some(l2),
        l2_gas_price: Some(l2p),
        l1_data_gas: Some(0),
        l1_data_gas_price: Some(0),
        ..FeeBounds::default()
    }
}

/// The default must never let a block body inject a tip.
#[test]
fn default_pins_tip_to_zero() {
    assert_eq!(FeeBounds::default().tip, 0);
    assert_eq!(FeeBounds::default().max_fee_fri, DEFAULT_MAX_FEE_FRI);
}

#[test]
fn estimate_is_scaled_by_multipliers() {
    let resolved = FeeBounds::default().resolve(&cheap_estimate()).unwrap();
    assert_eq!(resolved.l1_gas, 150);
    assert_eq!(resolved.l1_gas_price, 1_500);
    assert_eq!(resolved.l2_gas, 150_000);
    assert_eq!(resolved.tip, 0);
}

#[test]
fn explicit_fields_override_the_estimate() {
    let bounds = FeeBounds {
        l2_gas_price: Some(7),
        ..FeeBounds::default()
    };
    let resolved = bounds.resolve(&cheap_estimate()).unwrap();
    assert_eq!(resolved.l2_gas_price, 7, "explicit price must win");
    assert_eq!(resolved.l1_gas_price, 1_500, "others still scaled");
}

/// All six explicit means no estimate round trip.
#[test]
fn explicit_is_some_only_when_every_field_is_set() {
    assert!(FeeBounds::default().explicit().is_none());

    let full = explicit_bounds(1, 1, 1, 1);
    assert_eq!(full.explicit().unwrap().unwrap().l1_gas, 1);
}

/// The headline case: an inflated gas price must be refused.
#[test]
fn hostile_gas_price_trips_the_ceiling() {
    let hostile = FeeEstimateInput {
        l2_gas_price: 1_000_000_000_000_000, // 1e15 FRI per L2 gas unit
        ..cheap_estimate()
    };
    let err = FeeBounds::default()
        .resolve(&hostile)
        .unwrap_err()
        .to_string();
    assert!(err.contains("fee bounds exceeded"), "got: {err}");
}

/// The tip is charged per unit of L2 gas, so it counts against the ceiling
/// even when the estimate itself is honest.
#[test]
fn tip_counts_toward_the_ceiling() {
    let benign = FeeBounds::default().resolve(&cheap_estimate());
    assert!(benign.is_ok(), "honest estimate must pass");

    let tipped = FeeBounds {
        tip: 100_000_000_000_000,
        ..FeeBounds::default()
    };
    let err = tipped.resolve(&cheap_estimate()).unwrap_err().to_string();
    assert!(err.contains("fee bounds exceeded"), "got: {err}");
}

#[test]
fn overflow_is_rejected_not_wrapped() {
    let bounds = FeeBounds {
        max_fee_fri: u128::MAX,
        ..explicit_bounds(u64::MAX, u128::MAX, 1, 1)
    };
    let err = bounds.explicit().unwrap().unwrap_err().to_string();
    assert!(err.contains("overflow"), "got: {err}");
}

#[test]
fn nonsense_multipliers_are_rejected() {
    for m in [f64::NAN, f64::INFINITY, 0.0, -1.0] {
        for bounds in [
            FeeBounds {
                gas_multiplier: m,
                ..FeeBounds::default()
            },
            FeeBounds {
                price_multiplier: m,
                ..FeeBounds::default()
            },
            // Every gas amount is explicit, so `gas_multiplier` goes unused
            // — still a misconfiguration.
            FeeBounds {
                gas_multiplier: m,
                l1_gas: Some(1),
                l2_gas: Some(1),
                l1_data_gas: Some(1),
                ..FeeBounds::default()
            },
        ] {
            assert!(
                bounds.resolve(&cheap_estimate()).is_err(),
                "multiplier {m} should be rejected"
            );
        }
    }
}

/// A saturated amount paired with a zero price adds nothing to the total, so
/// the ceiling alone would let it through.
#[test]
fn saturating_scale_is_rejected() {
    let saturating = FeeEstimateInput {
        l2_gas_consumed: u64::MAX,
        l2_gas_price: 0,
        ..cheap_estimate()
    };
    let err = FeeBounds::default()
        .resolve(&saturating)
        .unwrap_err()
        .to_string();
    assert!(err.contains("overflows its bound"), "got: {err}");
}

/// A ceiling exactly equal to the resolved total is allowed.
#[test]
fn ceiling_is_inclusive() {
    let bounds = FeeBounds {
        max_fee_fri: 100,
        ..explicit_bounds(10, 10, 0, 0)
    };
    assert_eq!(bounds.explicit().unwrap().unwrap().l1_gas, 10);
}
