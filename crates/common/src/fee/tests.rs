use super::*;

fn bound(max_amount: u64, max_price_per_unit: u128) -> MaxBound {
    MaxBound {
        max_amount,
        max_price_per_unit,
    }
}

fn ceiling() -> ResourceBoundsCeiling {
    ResourceBoundsCeiling::new(bound(100, 10), bound(2_000, 20), bound(300, 30)).unwrap()
}

fn at_ceiling() -> ProposedResourceBounds {
    ProposedResourceBounds {
        l1_gas: bound(100, 10),
        l2_gas: bound(2_000, 20),
        l1_data_gas: bound(300, 30),
    }
}

#[test]
fn proposal_equal_to_ceiling_is_admitted() {
    assert_eq!(ceiling().admit(&at_ceiling()), Ok(()));
}

#[test]
fn zero_proposals_are_always_admitted() {
    let proposed = ProposedResourceBounds {
        l1_gas: bound(0, 0),
        l2_gas: bound(0, 0),
        l1_data_gas: bound(0, 0),
    };
    assert_eq!(ceiling().admit(&proposed), Ok(()));
}

#[test]
fn one_over_in_any_field_names_the_dimension_and_field() {
    for (index, dimension) in DIMENSIONS.into_iter().enumerate() {
        for field in ["max_amount", "max_price_per_unit"] {
            let mut proposed = at_ceiling();
            let target = match index {
                0 => &mut proposed.l1_gas,
                1 => &mut proposed.l2_gas,
                _ => &mut proposed.l1_data_gas,
            };
            let ceiling_value = if field == "max_amount" {
                target.max_amount += 1;
                u128::from(target.max_amount - 1)
            } else {
                target.max_price_per_unit += 1;
                target.max_price_per_unit - 1
            };

            assert_eq!(
                ceiling().admit(&proposed),
                Err(FeeCeilingError::Exceeded {
                    dimension,
                    field,
                    proposed: ceiling_value + 1,
                    ceiling: ceiling_value,
                }),
                "{dimension}.{field}"
            );
        }
    }
}

#[test]
fn zero_ceiling_fields_are_rejected_at_construction() {
    let zero = |dimension, field| Err(FeeCeilingError::ZeroCeiling { dimension, field });
    let one = bound(1, 1);

    assert_eq!(
        ResourceBoundsCeiling::new(bound(0, 1), one, one),
        zero("l1_gas", "max_amount")
    );
    assert_eq!(
        ResourceBoundsCeiling::new(one, bound(1, 0), one),
        zero("l2_gas", "max_price_per_unit")
    );
    assert_eq!(
        ResourceBoundsCeiling::new(one, one, bound(0, 1)),
        zero("l1_data_gas", "max_amount")
    );
    assert!(ResourceBoundsCeiling::new(one, one, one).is_ok());
}

#[test]
fn admit_revalidates_a_ceiling_that_bypassed_new() {
    let json = r#"{
        "l1_gas": {"max_amount": 0, "max_price_per_unit": 1},
        "l2_gas": {"max_amount": 1, "max_price_per_unit": 1},
        "l1_data_gas": {"max_amount": 1, "max_price_per_unit": 1}
    }"#;
    let ceiling: ResourceBoundsCeiling = serde_json::from_str(json).unwrap();

    let proposed = ProposedResourceBounds {
        l1_gas: bound(0, 1),
        l2_gas: bound(1, 1),
        l1_data_gas: bound(1, 1),
    };
    assert_eq!(
        ceiling.admit(&proposed),
        Err(FeeCeilingError::ZeroCeiling {
            dimension: "l1_gas",
            field: "max_amount",
        })
    );
}

#[test]
fn estimate_scaling_matches_starknet_rs_multiplier() {
    assert_eq!(
        MaxBound::from_estimate(1_000, 2_000),
        Ok(bound(1_500, 3_000))
    );
    // 7 * 1.5 = 10.5 truncates like the `as u128` cast in starknet-rs.
    assert_eq!(MaxBound::from_estimate(0, 7), Ok(bound(0, 10)));
    assert_eq!(
        MaxBound::from_estimate(1, u128::from(u64::MAX) + 1),
        Err(FeeCeilingError::EstimateOutOfRange)
    );

    assert_eq!(
        ProposedResourceBounds::from_estimate((10, 100), (20, 200), (30, 300)),
        Ok(ProposedResourceBounds {
            l1_gas: bound(15, 150),
            l2_gas: bound(30, 300),
            l1_data_gas: bound(45, 450),
        })
    );
    assert_eq!(
        ProposedResourceBounds::from_estimate((1, 1), (1, u128::MAX), (1, 1)),
        Err(FeeCeilingError::EstimateOutOfRange)
    );
}

#[test]
fn admit_estimate_scales_then_admits() {
    let ceiling =
        ResourceBoundsCeiling::new(bound(15, 150), bound(30, 300), bound(45, 450)).unwrap();
    assert_eq!(
        ceiling.admit_estimate((10, 100), (20, 200), (30, 300)),
        Ok(ProposedResourceBounds {
            l1_gas: bound(15, 150),
            l2_gas: bound(30, 300),
            l1_data_gas: bound(45, 450),
        })
    );
    assert_eq!(
        ceiling.admit_estimate((10, 100), (21, 200), (30, 300)),
        Err(FeeCeilingError::Exceeded {
            dimension: "l2_gas",
            field: "max_amount",
            proposed: 31,
            ceiling: 30,
        })
    );
}

#[test]
fn ceiling_serde_roundtrips() {
    let ceiling = ResourceBoundsCeiling::new(bound(1, 2), bound(3, 4), bound(5, 6)).unwrap();
    let json = serde_json::to_string(&ceiling).unwrap();
    assert_eq!(
        serde_json::from_str::<ResourceBoundsCeiling>(&json).unwrap(),
        ceiling
    );
}

#[test]
fn errors_name_the_offending_dimension() {
    assert_eq!(
        FeeCeilingError::Exceeded {
            dimension: "l2_gas",
            field: "max_price_per_unit",
            proposed: 30,
            ceiling: 20,
        }
        .to_string(),
        "proposed l2_gas.max_price_per_unit 30 exceeds fee ceiling 20"
    );
    assert_eq!(
        FeeCeilingError::ZeroCeiling {
            dimension: "l1_data_gas",
            field: "max_amount",
        }
        .to_string(),
        "fee ceiling l1_data_gas.max_amount must be greater than zero"
    );
}
