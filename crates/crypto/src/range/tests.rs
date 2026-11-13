use super::*;

#[test]
fn test_range_bit_size_boundaries() {
    for bit_size in [1, 128] {
        assert!(validate_bit_size(bit_size).is_ok());
    }
    for bit_size in [0, 129, usize::MAX] {
        assert!(validate_bit_size(bit_size).is_err());
    }
    assert!(compute_total_randomness(&[]).is_err());
}

#[test]
fn test_zero_bit_range_is_rejected_without_panic() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);
    let empty = Range {
        commitments: Vec::new(),
        proofs: Vec::new(),
    };

    assert!(prove(0, 0, &g1, &g2, &prefix).is_err());
    assert!(prove_with_randomness(0, 0, &g1, &g2, &prefix, &[]).is_err());
    assert!(verify(&empty, 0, &g1, &g2, &prefix).is_err());
}

#[test]
fn test_range_proof_small() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);

    let b = 7u128;
    let bit_size = 8;

    let (range, r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();
    let v = verify(&range, bit_size, &g1, &g2, &prefix).unwrap();

    // Check V = g1^b * g2^r
    let expected = StarkCurve::add(
        &StarkCurve::mul(&Felt::from(b), Some(&g1)),
        &StarkCurve::mul(&r, Some(&g2)),
    );

    let v_affine = StarkCurve::projective_to_affine(&v).unwrap();
    let expected_affine = StarkCurve::projective_to_affine(&expected).unwrap();

    assert_eq!(v_affine, expected_affine);
}

#[test]
fn test_range_proof_zero() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);

    let b = 0u128;
    let bit_size = 8;

    let (range, r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();
    let v = verify(&range, bit_size, &g1, &g2, &prefix).unwrap();

    // Check V = g1^0 * g2^r = g2^r
    let expected = StarkCurve::mul(&r, Some(&g2));

    let v_affine = StarkCurve::projective_to_affine(&v).unwrap();
    let expected_affine = StarkCurve::projective_to_affine(&expected).unwrap();

    assert_eq!(v_affine, expected_affine);
}

#[test]
fn test_range_proof_max_value() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);

    // Maximum value for 8 bits: 255
    let b = 255u128;
    let bit_size = 8;

    let (range, _r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();
    let result = verify(&range, bit_size, &g1, &g2, &prefix);
    assert!(result.is_ok());
}

#[test]
fn test_range_proof_out_of_range() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);

    // Value 256 is out of range for 8 bits (max is 255)
    let b = 256u128;
    let bit_size = 8;

    let result = prove(b, bit_size, &g1, &g2, &prefix);
    assert!(result.is_err());
    if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
        assert!(msg.contains("not in range"));
    }
}

#[test]
fn test_range_proof_bit_size_too_large() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);

    let b = 1u128;
    let bit_size = 129; // exceeds 128

    let result = prove(b, bit_size, &g1, &g2, &prefix);
    assert!(result.is_err());
    if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
        assert!(msg.contains("exceeds maximum 128"));
    }
}

#[test]
fn test_range_verify_length_mismatch() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);

    let b = 7u128;
    let bit_size = 8;

    let (range, _r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();

    // Verify with wrong bit_size
    let result = verify(&range, 16, &g1, &g2, &prefix);
    assert!(result.is_err());
    if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
        assert!(msg.contains("Length mismatch"));
    }
}

#[test]
fn test_range_verify_tampered_commitment() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);

    let b = 7u128;
    let bit_size = 8;

    let (mut range, _r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();

    // Tamper with first commitment
    range.commitments[0] =
        SerializablePoint::try_from_projective(&StarkCurve::generator()).unwrap();

    let result = verify(&range, bit_size, &g1, &g2, &prefix);
    assert!(result.is_err());
    if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
        assert!(msg.contains("Bit proof failed at index 0"));
    }
}

#[test]
fn test_range_verify_tampered_middle_commitment() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);

    let b = 7u128;
    let bit_size = 8;

    let (mut range, _r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();

    // Tamper with a middle commitment (index 3)
    range.commitments[3] =
        SerializablePoint::try_from_projective(&StarkCurve::generator()).unwrap();

    let result = verify(&range, bit_size, &g1, &g2, &prefix);
    assert!(result.is_err());
    if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
        assert!(msg.contains("Bit proof failed at index 3"));
    }
}

#[test]
fn test_range_proof_larger_value() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);

    // Test with a larger value
    let b = 12345u128;
    let bit_size = 16;

    let (range, r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();
    let v = verify(&range, bit_size, &g1, &g2, &prefix).unwrap();

    // Check V = g1^b * g2^r
    let expected = StarkCurve::add(
        &StarkCurve::mul(&Felt::from(b), Some(&g1)),
        &StarkCurve::mul(&r, Some(&g2)),
    );

    let v_affine = StarkCurve::projective_to_affine(&v).unwrap();
    let expected_affine = StarkCurve::projective_to_affine(&expected).unwrap();

    assert_eq!(v_affine, expected_affine);
}

#[test]
fn test_prove_with_randomness_same_as_prove() {
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();
    let prefix = Felt::from(42u64);

    let b = 7u128;
    let bit_size = 8;

    // Generate random values manually
    let random_values = random_felts(bit_size);

    // prove_with_randomness should produce valid proof
    let (range, r) = prove_with_randomness(b, bit_size, &g1, &g2, &prefix, &random_values).unwrap();
    let v = verify(&range, bit_size, &g1, &g2, &prefix).unwrap();

    // Check V = g1^b * g2^r
    let expected = StarkCurve::add(
        &StarkCurve::mul(&Felt::from(b), Some(&g1)),
        &StarkCurve::mul(&r, Some(&g2)),
    );

    let v_affine = StarkCurve::projective_to_affine(&v).unwrap();
    let expected_affine = StarkCurve::projective_to_affine(&expected).unwrap();
    assert_eq!(v_affine, expected_affine);

    // compute_total_randomness should give same r
    let r2 = compute_total_randomness(&random_values).unwrap();
    assert_eq!(r, r2);
}

/// Regression: compute_total_randomness must reject >128 elements (would panic on 1u128 << i).
#[test]
fn test_compute_total_randomness_rejects_oversized() {
    let values = random_felts(129);
    let result = compute_total_randomness(&values);
    assert!(result.is_err());
    if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
        assert!(msg.contains("exceeds maximum 128"));
    }
}
