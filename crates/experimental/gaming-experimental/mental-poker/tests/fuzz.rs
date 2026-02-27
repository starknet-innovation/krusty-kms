//! Fuzz tests for mental poker cryptographic operations using proptest.
//!
//! These tests help ensure correctness under a wide range of inputs,
//! catching edge cases and potential security issues.

use krusty_kms_crypto::StarkCurve;
use mental_poker::{
    types::{
        Card, CompactDLEqualityProof, CompactKeyOwnershipProof, CompactMaskedCard, CompactPoint,
        CompactRevealToken, CompactScalar, Permutation, SerializablePoint,
    },
    MentalPokerProtocol,
};
use proptest::prelude::*;
use starknet_types_core::felt::Felt;

// Strategy for generating random scalars (non-zero)
fn arb_nonzero_scalar() -> impl Strategy<Value = Felt> {
    (1u64..u64::MAX).prop_map(Felt::from)
}

// Strategy for generating random card indices
fn arb_card_index() -> impl Strategy<Value = u64> {
    1u64..1000
}

// Strategy for generating permutation sizes
fn arb_permutation_size() -> impl Strategy<Value = usize> {
    2usize..52
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    // ============================================
    // Key Generation Fuzz Tests
    // ============================================

    #[test]
    fn fuzz_keygen_produces_valid_keys(seed in any::<u64>()) {
        // Use seed to ensure reproducibility isn't required for this property
        let _ = seed;
        let (pk, sk) = MentalPokerProtocol::player_keygen();

        // Public key should be on the curve (not infinity)
        prop_assert!(!StarkCurve::is_infinity(&pk.point));

        // sk.public_key() should match pk
        let derived_pk = sk.public_key();
        let pk_affine = StarkCurve::projective_to_affine(&pk.point).unwrap();
        let derived_affine = StarkCurve::projective_to_affine(&derived_pk.point).unwrap();
        prop_assert_eq!(pk_affine.x(), derived_affine.x());
        prop_assert_eq!(pk_affine.y(), derived_affine.y());
    }

    #[test]
    fn fuzz_key_ownership_proof_roundtrip(context in prop::collection::vec(any::<u8>(), 0..100)) {
        let (pk, sk) = MentalPokerProtocol::player_keygen();

        // Generate and verify proof
        let proof = MentalPokerProtocol::prove_key_ownership(&pk, &sk, &context).unwrap();
        let valid = MentalPokerProtocol::verify_key_ownership(&pk, &proof, &context).unwrap();
        prop_assert!(valid, "Proof should be valid for same context");

        // Wrong context should fail
        let mut wrong_context = context.clone();
        wrong_context.push(0xFF);
        let valid_wrong = MentalPokerProtocol::verify_key_ownership(&pk, &proof, &wrong_context).unwrap();
        prop_assert!(!valid_wrong, "Proof should be invalid for different context");
    }

    // ============================================
    // Card Masking/Unmasking Fuzz Tests
    // ============================================

    #[test]
    fn fuzz_mask_unmask_roundtrip(card_idx in arb_card_index()) {
        let (pk1, sk1) = MentalPokerProtocol::player_keygen();
        let (pk2, sk2) = MentalPokerProtocol::player_keygen();

        // Aggregate keys
        let aggregate_pk = pk1.add(&pk2);

        // Create and mask card
        let card = Card::from_index(card_idx);
        let (masked, proof) = MentalPokerProtocol::mask(&card, &aggregate_pk, None).unwrap();

        // Verify mask proof
        let mask_valid = MentalPokerProtocol::verify_mask(&card, &masked, &aggregate_pk, &proof).unwrap();
        prop_assert!(mask_valid, "Mask proof should be valid");

        // Compute reveal tokens from both players
        let (token1, proof1) = MentalPokerProtocol::compute_reveal_token(&masked, &sk1, &pk1).unwrap();
        let (token2, proof2) = MentalPokerProtocol::compute_reveal_token(&masked, &sk2, &pk2).unwrap();

        // Verify reveal token proofs
        let token1_valid = MentalPokerProtocol::verify_reveal_token(&masked, &token1, &pk1, &proof1).unwrap();
        let token2_valid = MentalPokerProtocol::verify_reveal_token(&masked, &token2, &pk2, &proof2).unwrap();
        prop_assert!(token1_valid && token2_valid, "Reveal token proofs should be valid");

        // Unmask using the API that takes tokens with proofs
        let reveal_tokens = vec![
            (token1, proof1, pk1),
            (token2, proof2, pk2),
        ];
        let revealed = MentalPokerProtocol::unmask(&masked, &reveal_tokens).unwrap();

        // Revealed card should match original (compare using affine coordinates)
        let card_affine = StarkCurve::projective_to_affine(&card.point).unwrap();
        let revealed_affine = StarkCurve::projective_to_affine(&revealed.point).unwrap();
        prop_assert_eq!(card_affine.x(), revealed_affine.x(), "Unmasked card x should match");
        prop_assert_eq!(card_affine.y(), revealed_affine.y(), "Unmasked card y should match");
    }

    #[test]
    fn fuzz_remask_preserves_card(card_idx in arb_card_index()) {
        let (pk, sk) = MentalPokerProtocol::player_keygen();
        let card = Card::from_index(card_idx);

        // Initial mask
        let (masked, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();

        // Remask multiple times
        let (remasked1, _) = MentalPokerProtocol::remask(&masked, &pk, None).unwrap();
        let (remasked2, _) = MentalPokerProtocol::remask(&remasked1, &pk, None).unwrap();

        // All masks should decrypt to same card
        let (token, proof) = MentalPokerProtocol::compute_reveal_token(&masked, &sk, &pk).unwrap();
        let (token1, proof1) = MentalPokerProtocol::compute_reveal_token(&remasked1, &sk, &pk).unwrap();
        let (token2, proof2) = MentalPokerProtocol::compute_reveal_token(&remasked2, &sk, &pk).unwrap();

        let revealed = MentalPokerProtocol::unmask(&masked, &[(token, proof, pk.clone())]).unwrap();
        let revealed1 = MentalPokerProtocol::unmask(&remasked1, &[(token1, proof1, pk.clone())]).unwrap();
        let revealed2 = MentalPokerProtocol::unmask(&remasked2, &[(token2, proof2, pk.clone())]).unwrap();

        // Compare using affine coordinates to avoid move issues
        let card_affine = StarkCurve::projective_to_affine(&card.point).unwrap();
        let revealed_affine = StarkCurve::projective_to_affine(&revealed.point).unwrap();
        let revealed1_affine = StarkCurve::projective_to_affine(&revealed1.point).unwrap();
        let revealed2_affine = StarkCurve::projective_to_affine(&revealed2.point).unwrap();

        prop_assert_eq!(card_affine.x(), revealed_affine.x());
        prop_assert_eq!(card_affine.y(), revealed_affine.y());
        prop_assert_eq!(card_affine.x(), revealed1_affine.x());
        prop_assert_eq!(card_affine.y(), revealed1_affine.y());
        prop_assert_eq!(card_affine.x(), revealed2_affine.x());
        prop_assert_eq!(card_affine.y(), revealed2_affine.y());
    }

    // ============================================
    // Serialization Fuzz Tests
    // ============================================

    #[test]
    fn fuzz_compact_point_roundtrip(scalar in arb_nonzero_scalar()) {
        let point = StarkCurve::mul_generator(&scalar);
        let compact = CompactPoint::from_projective(&point).unwrap();
        let recovered = compact.to_projective().unwrap();
        prop_assert_eq!(point, recovered);
    }

    #[test]
    fn fuzz_compact_point_raw_bytes_roundtrip(scalar in arb_nonzero_scalar()) {
        let point = StarkCurve::mul_generator(&scalar);
        let compact = CompactPoint::from_projective(&point).unwrap();
        let raw = compact.to_raw_bytes();
        let recovered = CompactPoint::from_raw_bytes(&raw);
        prop_assert_eq!(compact, recovered);
    }

    #[test]
    fn fuzz_compact_scalar_roundtrip(value in any::<u64>()) {
        let felt = Felt::from(value);
        let compact = CompactScalar::from_felt(&felt);
        let recovered = compact.to_felt();
        prop_assert_eq!(felt, recovered);
    }

    #[test]
    fn fuzz_serializable_point_compact_roundtrip(scalar in arb_nonzero_scalar()) {
        let point = StarkCurve::mul_generator(&scalar);
        let serializable = SerializablePoint::from_projective(&point).unwrap();
        let compact = serializable.to_bytes().unwrap();
        let recovered_serializable = SerializablePoint::from_bytes(&compact).unwrap();
        prop_assert_eq!(serializable, recovered_serializable);
    }

    #[test]
    fn fuzz_compact_masked_card_roundtrip(card_idx in arb_card_index()) {
        let (pk, _) = MentalPokerProtocol::player_keygen();
        let card = Card::from_index(card_idx);
        let (masked, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();

        let compact = CompactMaskedCard::from_masked_card(&masked).unwrap();
        let recovered = compact.to_masked_card().unwrap();

        prop_assert_eq!(masked.c0, recovered.c0);
        prop_assert_eq!(masked.c1, recovered.c1);
    }

    #[test]
    fn fuzz_compact_reveal_token_roundtrip(card_idx in arb_card_index()) {
        let (pk, sk) = MentalPokerProtocol::player_keygen();
        let card = Card::from_index(card_idx);
        let (masked, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();
        let (token, _) = MentalPokerProtocol::compute_reveal_token(&masked, &sk, &pk).unwrap();

        let compact = CompactRevealToken::from_reveal_token(&token).unwrap();
        let recovered = compact.to_reveal_token().unwrap();

        let token_affine = StarkCurve::projective_to_affine(&token.point).unwrap();
        let recovered_affine = StarkCurve::projective_to_affine(&recovered.point).unwrap();
        prop_assert_eq!(token_affine.x(), recovered_affine.x());
        prop_assert_eq!(token_affine.y(), recovered_affine.y());
    }

    #[test]
    fn fuzz_compact_key_ownership_proof_roundtrip(context in prop::collection::vec(any::<u8>(), 0..50)) {
        let (pk, sk) = MentalPokerProtocol::player_keygen();
        let proof = MentalPokerProtocol::prove_key_ownership(&pk, &sk, &context).unwrap();

        let compact = CompactKeyOwnershipProof::from_proof(&proof).unwrap();
        let recovered = compact.to_proof().unwrap();

        // Verify the recovered proof still validates
        let valid = MentalPokerProtocol::verify_key_ownership(&pk, &recovered, &context).unwrap();
        prop_assert!(valid, "Recovered proof should still be valid");
    }

    #[test]
    fn fuzz_compact_dl_equality_proof_roundtrip(card_idx in arb_card_index()) {
        let (pk, _) = MentalPokerProtocol::player_keygen();
        let card = Card::from_index(card_idx);
        let (masked, proof) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();

        let compact = CompactDLEqualityProof::from_proof(&proof).unwrap();
        let recovered = compact.to_proof().unwrap();

        // Verify the recovered proof still validates
        let valid = MentalPokerProtocol::verify_mask(&card, &masked, &pk, &recovered).unwrap();
        prop_assert!(valid, "Recovered proof should still be valid");
    }

    // ============================================
    // Permutation Fuzz Tests
    // ============================================

    #[test]
    fn fuzz_permutation_is_valid(size in arb_permutation_size()) {
        let perm = Permutation::random(size);
        prop_assert_eq!(perm.len(), size);

        // Check it's a valid permutation (bijection)
        let mut sorted = perm.indices.clone();
        sorted.sort();
        let expected: Vec<usize> = (0..size).collect();
        prop_assert_eq!(sorted, expected, "Permutation should contain all indices exactly once");
    }

    #[test]
    fn fuzz_permutation_shuffle_preserves_elements(size in arb_permutation_size()) {
        let perm = Permutation::random(size);
        let original: Vec<u64> = (0..size as u64).collect();
        let shuffled = perm.permute(&original);

        // Shuffled should have same elements (but different order, usually)
        let mut shuffled_sorted = shuffled.clone();
        shuffled_sorted.sort();
        prop_assert_eq!(shuffled_sorted, original, "Shuffle should preserve all elements");
    }

    // ============================================
    // Multi-Player Protocol Fuzz Tests
    // ============================================

    #[test]
    fn fuzz_aggregate_key_commutativity(seed in any::<u64>()) {
        let _ = seed;
        let (pk1, _) = MentalPokerProtocol::player_keygen();
        let (pk2, _) = MentalPokerProtocol::player_keygen();
        let (pk3, _) = MentalPokerProtocol::player_keygen();

        // Different orderings should produce same aggregate
        let agg1 = pk1.add(&pk2).add(&pk3);
        let agg2 = pk3.add(&pk1).add(&pk2);
        let agg3 = pk2.add(&pk3).add(&pk1);

        // Compare the points (they don't implement Eq for proptest comparison)
        let agg1_affine = StarkCurve::projective_to_affine(&agg1.point).unwrap();
        let agg2_affine = StarkCurve::projective_to_affine(&agg2.point).unwrap();
        let agg3_affine = StarkCurve::projective_to_affine(&agg3.point).unwrap();

        prop_assert_eq!(agg1_affine.x(), agg2_affine.x());
        prop_assert_eq!(agg1_affine.y(), agg2_affine.y());
        prop_assert_eq!(agg2_affine.x(), agg3_affine.x());
        prop_assert_eq!(agg2_affine.y(), agg3_affine.y());
    }

    #[test]
    fn fuzz_reveal_token_additivity(card_idx in arb_card_index()) {
        let (pk1, sk1) = MentalPokerProtocol::player_keygen();
        let (pk2, sk2) = MentalPokerProtocol::player_keygen();
        let aggregate_pk = pk1.add(&pk2);

        let card = Card::from_index(card_idx);
        let (masked, _) = MentalPokerProtocol::mask(&card, &aggregate_pk, None).unwrap();

        // Compute individual tokens with proofs
        let (token1, proof1) = MentalPokerProtocol::compute_reveal_token(&masked, &sk1, &pk1).unwrap();
        let (token2, proof2) = MentalPokerProtocol::compute_reveal_token(&masked, &sk2, &pk2).unwrap();

        // Unmask using the API with proofs - different orderings
        let revealed1 = MentalPokerProtocol::unmask(&masked, &[
            (token1.clone(), proof1.clone(), pk1.clone()),
            (token2.clone(), proof2.clone(), pk2.clone()),
        ]).unwrap();
        let revealed2 = MentalPokerProtocol::unmask(&masked, &[
            (token2, proof2, pk2),
            (token1, proof1, pk1),
        ]).unwrap();

        // Compare using affine coordinates
        let r1_affine = StarkCurve::projective_to_affine(&revealed1.point).unwrap();
        let r2_affine = StarkCurve::projective_to_affine(&revealed2.point).unwrap();
        let card_affine = StarkCurve::projective_to_affine(&card.point).unwrap();

        prop_assert_eq!(r1_affine.x(), r2_affine.x());
        prop_assert_eq!(r1_affine.y(), r2_affine.y());
        prop_assert_eq!(r1_affine.x(), card_affine.x());
        prop_assert_eq!(r1_affine.y(), card_affine.y());
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn fuzz_different_cards_mask_differently(idx1 in arb_card_index(), idx2 in arb_card_index()) {
        prop_assume!(idx1 != idx2);

        let (pk, _) = MentalPokerProtocol::player_keygen();
        let card1 = Card::from_index(idx1);
        let card2 = Card::from_index(idx2);

        let (masked1, _) = MentalPokerProtocol::mask(&card1, &pk, None).unwrap();
        let (masked2, _) = MentalPokerProtocol::mask(&card2, &pk, None).unwrap();

        // Different cards should produce different masked cards (with overwhelming probability)
        // Note: We check c1 which contains the encrypted card value
        prop_assert_ne!(masked1.c1, masked2.c1, "Different cards should produce different c1 components");
    }

    #[test]
    fn fuzz_same_card_different_randomness(card_idx in arb_card_index()) {
        let (pk, _) = MentalPokerProtocol::player_keygen();
        let card = Card::from_index(card_idx);

        // Mask same card twice (with different randomness)
        let (masked1, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();
        let (masked2, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();

        // Should produce different ciphertexts (with overwhelming probability)
        prop_assert_ne!(masked1.c0, masked2.c0, "Same card with different randomness should have different c0");
    }
}

// ============================================
// Additional Property Tests (Non-proptest)
// ============================================

#[test]
fn test_proof_security_invalid_key_fails() {
    let (pk1, sk1) = MentalPokerProtocol::player_keygen();
    let (pk2, _sk2) = MentalPokerProtocol::player_keygen();

    // Generate proof for pk1
    let proof = MentalPokerProtocol::prove_key_ownership(&pk1, &sk1, b"test").unwrap();

    // Verify with wrong public key should fail
    let valid = MentalPokerProtocol::verify_key_ownership(&pk2, &proof, b"test").unwrap();
    assert!(!valid, "Proof should not verify with different public key");
}

#[test]
fn test_reveal_token_with_wrong_key_fails() {
    let (pk1, sk1) = MentalPokerProtocol::player_keygen();
    let (pk2, _sk2) = MentalPokerProtocol::player_keygen();
    let aggregate_pk = pk1.add(&pk2);

    let card = Card::from_index(42);
    let (masked, _) = MentalPokerProtocol::mask(&card, &aggregate_pk, None).unwrap();

    // Token computed with sk1 should not verify with pk2
    let (token, proof) = MentalPokerProtocol::compute_reveal_token(&masked, &sk1, &pk1).unwrap();
    let valid = MentalPokerProtocol::verify_reveal_token(&masked, &token, &pk2, &proof).unwrap();
    assert!(
        !valid,
        "Token proof should not verify with wrong public key"
    );
}

#[test]
fn test_mask_proof_with_wrong_card_fails() {
    let (pk, _) = MentalPokerProtocol::player_keygen();

    let card1 = Card::from_index(1);
    let card2 = Card::from_index(2);

    let (masked, proof) = MentalPokerProtocol::mask(&card1, &pk, None).unwrap();

    // Proof for card1 should not verify with card2
    let valid = MentalPokerProtocol::verify_mask(&card2, &masked, &pk, &proof).unwrap();
    assert!(!valid, "Mask proof should not verify with different card");
}
