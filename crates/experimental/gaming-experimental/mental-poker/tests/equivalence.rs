//! Equivalence tests and test vectors for mental poker protocol.
//!
//! These tests verify that our implementation produces correct cryptographic
//! operations by checking:
//! 1. Deterministic operations with known inputs
//! 2. Round-trip correctness (encrypt then decrypt)
//! 3. Proof verification
//! 4. Multi-player scenarios

use mental_poker::{
    deck::{CardEncoding, Hand, MaskedDeck, PlayingCard, Rank, Suit},
    protocol::MentalPokerProtocol,
    types::{Card, MaskedCard, Permutation, PublicKey},
};
use krusty_kms_crypto::StarkCurve;
use starknet_types_core::felt::Felt;

// ====================
// Test Vector Tests
// ====================

/// Test that key generation produces valid public keys
#[test]
fn test_keygen_produces_valid_keys() {
    for _ in 0..10 {
        let (pk, sk) = MentalPokerProtocol::player_keygen();

        // Public key should not be identity
        assert!(!StarkCurve::is_infinity(&pk.point));

        // Public key should equal g^sk
        let expected_pk = StarkCurve::mul_generator(&sk.scalar);
        assert_eq!(pk.point, expected_pk);
    }
}

/// Test that card indexing is deterministic
#[test]
fn test_card_index_determinism() {
    // Same index should always produce same card
    let card1_a = Card::from_index(1);
    let card1_b = Card::from_index(1);
    assert_eq!(card1_a.point, card1_b.point);

    let card42_a = Card::from_index(42);
    let card42_b = Card::from_index(42);
    assert_eq!(card42_a.point, card42_b.point);

    // Different indices should produce different cards
    let card1 = Card::from_index(1);
    let card2 = Card::from_index(2);
    assert_ne!(card1.point, card2.point);
}

/// Test known scalar multiplication
#[test]
fn test_scalar_mul_known_values() {
    // g^1 should equal the generator
    let card1 = Card::from_index(1);
    assert_eq!(card1.point, StarkCurve::GENERATOR);

    // g^2 should be g + g
    let card2 = Card::from_index(2);
    let g_plus_g = StarkCurve::add(&StarkCurve::GENERATOR, &StarkCurve::GENERATOR);
    assert_eq!(card2.point, g_plus_g);
}

// ====================
// ElGamal Correctness
// ====================

/// Test that ElGamal encryption/decryption round-trips correctly
#[test]
fn test_elgamal_round_trip() {
    let (pk, sk) = MentalPokerProtocol::player_keygen();

    // Test with multiple cards
    for i in 1..=10 {
        let card = Card::from_index(i);

        // Mask the card (encrypt)
        let (masked, _proof) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();

        // Compute reveal token (partial decryption)
        let (token, proof) = MentalPokerProtocol::compute_reveal_token(&masked, &sk, &pk).unwrap();

        // Verify reveal token
        let valid = MentalPokerProtocol::verify_reveal_token(&masked, &token, &pk, &proof).unwrap();
        assert!(valid, "Reveal token should be valid");

        // Unmask (decrypt)
        let tokens = vec![(token, proof, pk.clone())];
        let revealed = MentalPokerProtocol::unmask(&masked, &tokens).unwrap();

        // Should get original card back
        assert_eq!(
            revealed.point, card.point,
            "Round-trip should preserve card"
        );
    }
}

/// Test multi-player ElGamal (threshold decryption)
#[test]
fn test_multiparty_elgamal() {
    // Setup 3 players
    let (pk1, sk1) = MentalPokerProtocol::player_keygen();
    let (pk2, sk2) = MentalPokerProtocol::player_keygen();
    let (pk3, sk3) = MentalPokerProtocol::player_keygen();

    // Aggregate public key
    let aggregate_pk = pk1.add(&pk2).add(&pk3);

    let card = Card::from_index(42);

    // Encrypt under aggregate key
    let (masked, _) = MentalPokerProtocol::mask(&card, &aggregate_pk, None).unwrap();

    // Each player computes their reveal token
    let (token1, proof1) = MentalPokerProtocol::compute_reveal_token(&masked, &sk1, &pk1).unwrap();
    let (token2, proof2) = MentalPokerProtocol::compute_reveal_token(&masked, &sk2, &pk2).unwrap();
    let (token3, proof3) = MentalPokerProtocol::compute_reveal_token(&masked, &sk3, &pk3).unwrap();

    // Decrypt with all tokens
    let tokens = vec![
        (token1, proof1, pk1),
        (token2, proof2, pk2),
        (token3, proof3, pk3),
    ];
    let revealed = MentalPokerProtocol::unmask(&masked, &tokens).unwrap();

    assert_eq!(
        revealed.point, card.point,
        "Multi-party decryption should work"
    );
}

// ====================
// Proof Verification
// ====================

/// Test Schnorr proof correctness
#[test]
fn test_schnorr_proof_verification() {
    let (pk, sk) = MentalPokerProtocol::player_keygen();

    // Valid proof should verify
    let context = b"test_context";
    let proof = MentalPokerProtocol::prove_key_ownership(&pk, &sk, context).unwrap();
    let valid = MentalPokerProtocol::verify_key_ownership(&pk, &proof, context).unwrap();
    assert!(valid, "Valid proof should verify");

    // Wrong context should fail
    let wrong_context = b"wrong_context";
    let invalid =
        MentalPokerProtocol::verify_key_ownership(&pk, &proof, wrong_context).unwrap_or(false);
    assert!(!invalid, "Wrong context should fail");

    // Wrong key should fail
    let (other_pk, _) = MentalPokerProtocol::player_keygen();
    let invalid =
        MentalPokerProtocol::verify_key_ownership(&other_pk, &proof, context).unwrap_or(false);
    assert!(!invalid, "Wrong key should fail");
}

/// Test DL equality proof (Chaum-Pedersen)
#[test]
fn test_dl_equality_proof_verification() {
    let (pk, sk) = MentalPokerProtocol::player_keygen();
    let card = Card::from_index(7);
    let (masked, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();

    // Compute reveal token with proof
    let (token, proof) = MentalPokerProtocol::compute_reveal_token(&masked, &sk, &pk).unwrap();

    // Proof should verify
    let valid = MentalPokerProtocol::verify_reveal_token(&masked, &token, &pk, &proof).unwrap();
    assert!(valid, "Valid DL equality proof should verify");
}

// ====================
// Remasking Tests
// ====================

/// Test that remasking preserves the underlying plaintext
#[test]
fn test_remasking_preserves_plaintext() {
    let (pk, sk) = MentalPokerProtocol::player_keygen();
    let card = Card::from_index(13);

    // Initial encryption
    let (masked, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();

    // Remask multiple times
    let (remasked1, _) = MentalPokerProtocol::remask(&masked, &pk, None).unwrap();
    let (remasked2, _) = MentalPokerProtocol::remask(&remasked1, &pk, None).unwrap();
    let (remasked3, _) = MentalPokerProtocol::remask(&remasked2, &pk, None).unwrap();

    // Ciphertexts should all be different
    assert_ne!(masked.c0, remasked1.c0);
    assert_ne!(remasked1.c0, remasked2.c0);
    assert_ne!(remasked2.c0, remasked3.c0);

    // But all should decrypt to the same plaintext
    let (token, proof) = MentalPokerProtocol::compute_reveal_token(&remasked3, &sk, &pk).unwrap();
    let tokens = vec![(token, proof, pk)];
    let revealed = MentalPokerProtocol::unmask(&remasked3, &tokens).unwrap();

    assert_eq!(
        revealed.point, card.point,
        "Remasking should preserve plaintext"
    );
}

// ====================
// Shuffling Tests
// ====================

/// Test that shuffle permutes cards correctly
#[test]
fn test_shuffle_permutation() {
    let (pk, _sk) = MentalPokerProtocol::player_keygen();

    // Create small deck
    let cards: Vec<Card> = (1..=5).map(Card::from_index).collect();
    let masked_deck: Vec<MaskedCard> = cards
        .iter()
        .map(|c| MentalPokerProtocol::mask(c, &pk, None).unwrap().0)
        .collect();

    // Known permutation: [3, 1, 4, 0, 2] (indices)
    let perm = Permutation::new(vec![3, 1, 4, 0, 2]);
    let factors: Vec<Felt> = (0..5).map(|_| krusty_kms_crypto::scalar::random_felt()).collect();

    let shuffled =
        MentalPokerProtocol::shuffle_and_remask(&masked_deck, &pk, &perm, &factors).unwrap();

    // Verify we got 5 cards back
    assert_eq!(shuffled.len(), 5);

    // Cards should be different (due to remasking)
    for i in 0..5 {
        assert_ne!(
            masked_deck[i].c0, shuffled[i].0.c0,
            "Shuffle should remask cards"
        );
    }
}

/// Test shuffle preserves deck size
#[test]
fn test_shuffle_preserves_size() {
    let encoding = CardEncoding::standard_deck();
    let (pk, _) = MentalPokerProtocol::player_keygen();

    let deck = MaskedDeck::standard(&encoding, &pk).unwrap();
    assert_eq!(deck.len(), 52);

    let shuffled = deck.shuffle(&pk).unwrap();
    assert_eq!(shuffled.len(), 52);
}

// ====================
// Full Game Simulation
// ====================

/// Simulate a 2-player poker deal
#[test]
fn test_two_player_poker_deal() {
    let encoding = CardEncoding::standard_deck();

    // Two players setup
    let (pk1, sk1) = MentalPokerProtocol::player_keygen();
    let (pk2, sk2) = MentalPokerProtocol::player_keygen();

    // Prove key ownership
    let proof1 = MentalPokerProtocol::prove_key_ownership(&pk1, &sk1, b"player1").unwrap();
    let proof2 = MentalPokerProtocol::prove_key_ownership(&pk2, &sk2, b"player2").unwrap();

    // Compute aggregate key
    let keys = vec![
        (pk1.clone(), proof1, b"player1".to_vec()),
        (pk2.clone(), proof2, b"player2".to_vec()),
    ];
    let aggregate_pk = MentalPokerProtocol::compute_aggregate_key(&keys).unwrap();

    // Create and shuffle deck
    let mut deck = MaskedDeck::standard(&encoding, &aggregate_pk).unwrap();

    // Player 1 shuffles
    deck = deck.shuffle(&aggregate_pk).unwrap();

    // Player 2 shuffles
    deck = deck.shuffle(&aggregate_pk).unwrap();

    // Deal 2 cards to each player
    let player1_card1 = deck.draw().unwrap();
    let _player2_card1 = deck.draw().unwrap();
    let _player1_card2 = deck.draw().unwrap();
    let _player2_card2 = deck.draw().unwrap();

    // Both players reveal player 1's first card
    let (token1_p1c1, proof1_p1c1) =
        MentalPokerProtocol::compute_reveal_token(&player1_card1, &sk1, &pk1).unwrap();
    let (token2_p1c1, proof2_p1c1) =
        MentalPokerProtocol::compute_reveal_token(&player1_card1, &sk2, &pk2).unwrap();

    let tokens_p1c1 = vec![
        (token1_p1c1, proof1_p1c1, pk1.clone()),
        (token2_p1c1, proof2_p1c1, pk2.clone()),
    ];

    let revealed_card = MentalPokerProtocol::unmask(&player1_card1, &tokens_p1c1).unwrap();
    let playing_card = encoding.decode(&revealed_card).unwrap();

    // Verify we got a valid card
    assert!(
        Suit::ALL.contains(&playing_card.suit),
        "Should be a valid suit"
    );
    assert!(
        Rank::ALL.contains(&playing_card.rank),
        "Should be a valid rank"
    );

    // Remaining deck should have 48 cards
    assert_eq!(deck.len(), 48);
}

/// Test that all 52 cards can be uniquely decoded
#[test]
fn test_all_cards_unique() {
    let encoding = CardEncoding::standard_deck();

    // Verify we have 52 unique cards
    let all_cards = encoding.all_cards();
    assert_eq!(all_cards.len(), 52);

    // All cards should decode to different playing cards
    let mut seen = std::collections::HashSet::new();
    for card in &all_cards {
        let playing = encoding.decode(card).unwrap();
        assert!(
            seen.insert(playing),
            "Each card should decode to unique playing card"
        );
    }
    assert_eq!(seen.len(), 52);
}

/// Test Hand management
#[test]
fn test_hand_operations() {
    let encoding = CardEncoding::standard_deck();
    let (pk, sk) = MentalPokerProtocol::player_keygen();

    // Create a hand with specific cards
    let cards_to_add = vec![
        PlayingCard::new(Rank::Ace, Suit::Spades),
        PlayingCard::new(Rank::King, Suit::Hearts),
        PlayingCard::new(Rank::Queen, Suit::Diamonds),
    ];

    let mut hand = Hand::new();
    let mut original_masked = Vec::new();

    for playing in &cards_to_add {
        let card = encoding.encode(playing).unwrap();
        let (masked, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();
        original_masked.push(masked.clone());
        hand.add(masked);
    }

    assert_eq!(hand.len(), 3);

    // Reveal each card
    for (i, playing) in cards_to_add.iter().enumerate() {
        let (token, proof) =
            MentalPokerProtocol::compute_reveal_token(&original_masked[i], &sk, &pk).unwrap();
        let tokens = vec![(token, proof, pk.clone())];

        // Use the stored masked card for reveal
        let revealed = MentalPokerProtocol::unmask(&original_masked[i], &tokens).unwrap();
        let decoded = encoding.decode(&revealed).unwrap();
        assert_eq!(decoded, *playing, "Card {} should match", i);
    }
}

// ====================
// Edge Cases
// ====================

/// Test with minimum valid card index
#[test]
fn test_min_card_index() {
    let (pk, sk) = MentalPokerProtocol::player_keygen();
    let card = Card::from_index(1); // Minimum valid index

    let (masked, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();
    let (token, proof) = MentalPokerProtocol::compute_reveal_token(&masked, &sk, &pk).unwrap();
    let tokens = vec![(token, proof, pk)];
    let revealed = MentalPokerProtocol::unmask(&masked, &tokens).unwrap();

    assert_eq!(revealed.point, card.point);
}

/// Test with large card index
#[test]
fn test_large_card_index() {
    let (pk, sk) = MentalPokerProtocol::player_keygen();
    let card = Card::from_index(1_000_000); // Large index

    let (masked, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();
    let (token, proof) = MentalPokerProtocol::compute_reveal_token(&masked, &sk, &pk).unwrap();
    let tokens = vec![(token, proof, pk)];
    let revealed = MentalPokerProtocol::unmask(&masked, &tokens).unwrap();

    assert_eq!(revealed.point, card.point);
}

/// Test aggregate key with 5 players
#[test]
fn test_five_player_aggregate_key() {
    let players: Vec<_> = (0..5)
        .map(|i| {
            let (pk, sk) = MentalPokerProtocol::player_keygen();
            let context = format!("player{}", i);
            let proof =
                MentalPokerProtocol::prove_key_ownership(&pk, &sk, context.as_bytes()).unwrap();
            (pk, sk, proof, context.into_bytes())
        })
        .collect();

    // Compute aggregate key
    let keys: Vec<_> = players
        .iter()
        .map(|(pk, _, proof, ctx)| (pk.clone(), proof.clone(), ctx.clone()))
        .collect();
    let aggregate_pk = MentalPokerProtocol::compute_aggregate_key(&keys).unwrap();

    // Verify aggregate is sum of all public keys
    let mut expected = PublicKey::zero();
    for (pk, _, _, _) in &players {
        expected = expected.add(pk);
    }
    assert_eq!(aggregate_pk.point, expected.point);

    // Test encryption/decryption with all 5 players
    let card = Card::from_index(7);
    let (masked, _) = MentalPokerProtocol::mask(&card, &aggregate_pk, None).unwrap();

    let tokens: Vec<_> = players
        .iter()
        .map(|(pk, sk, _, _)| {
            let (token, proof) =
                MentalPokerProtocol::compute_reveal_token(&masked, sk, pk).unwrap();
            (token, proof, pk.clone())
        })
        .collect();

    let revealed = MentalPokerProtocol::unmask(&masked, &tokens).unwrap();
    assert_eq!(revealed.point, card.point);
}

// ====================
// Shuffle Proof Tests
// ====================

/// Test shuffle with proof generation and verification
#[test]
fn test_shuffle_with_proof() {
    use mental_poker::shuffle::{
        ShuffleArgument, ShuffleParameters, ShuffleStatement, ShuffleWitness,
    };
    use krusty_kms_crypto::scalar;

    let (pk, _sk) = MentalPokerProtocol::player_keygen();

    // Create a small deck
    let n = 6;
    let cards: Vec<Card> = (1..=n).map(|i| Card::from_index(i as u64)).collect();
    let input_deck: Vec<MaskedCard> = cards
        .iter()
        .map(|c| MentalPokerProtocol::mask(c, &pk, None).unwrap().0)
        .collect();

    // Create random permutation and randomness
    let permutation = Permutation::random(n);
    let randomness: Vec<starknet_types_core::felt::Felt> =
        (0..n).map(|_| scalar::random_felt()).collect();

    // Apply shuffle using the protocol function
    let (output_deck, proof) = MentalPokerProtocol::shuffle_and_remask_with_proof(
        &input_deck,
        &pk,
        &permutation,
        &randomness,
    )
    .unwrap();

    // Verify the proof
    let valid =
        MentalPokerProtocol::verify_shuffle(&input_deck, &output_deck, &pk, &proof).unwrap();

    assert!(valid, "Shuffle proof should verify");
}

/// Test that shuffle proof fails for tampered output
#[test]
fn test_shuffle_proof_detects_tampering() {
    use krusty_kms_crypto::scalar;

    let (pk, _sk) = MentalPokerProtocol::player_keygen();

    let n = 4;
    let cards: Vec<Card> = (1..=n).map(|i| Card::from_index(i as u64)).collect();
    let input_deck: Vec<MaskedCard> = cards
        .iter()
        .map(|c| MentalPokerProtocol::mask(c, &pk, None).unwrap().0)
        .collect();

    let permutation = Permutation::random(n);
    let randomness: Vec<starknet_types_core::felt::Felt> =
        (0..n).map(|_| scalar::random_felt()).collect();

    let (mut output_deck, proof) = MentalPokerProtocol::shuffle_and_remask_with_proof(
        &input_deck,
        &pk,
        &permutation,
        &randomness,
    )
    .unwrap();

    // Tamper with the output by swapping two cards
    output_deck.swap(0, 1);

    // Verification should fail
    let valid =
        MentalPokerProtocol::verify_shuffle(&input_deck, &output_deck, &pk, &proof).unwrap();

    assert!(!valid, "Tampered shuffle should not verify");
}

/// Test multi-player shuffle sequence with proofs
#[test]
fn test_multiplayer_shuffle_with_proofs() {
    use krusty_kms_crypto::scalar;

    // Setup 3 players
    let (pk1, sk1) = MentalPokerProtocol::player_keygen();
    let (pk2, sk2) = MentalPokerProtocol::player_keygen();
    let (pk3, sk3) = MentalPokerProtocol::player_keygen();

    let proof1 = MentalPokerProtocol::prove_key_ownership(&pk1, &sk1, b"p1").unwrap();
    let proof2 = MentalPokerProtocol::prove_key_ownership(&pk2, &sk2, b"p2").unwrap();
    let proof3 = MentalPokerProtocol::prove_key_ownership(&pk3, &sk3, b"p3").unwrap();

    let keys = vec![
        (pk1.clone(), proof1, b"p1".to_vec()),
        (pk2.clone(), proof2, b"p2".to_vec()),
        (pk3.clone(), proof3, b"p3".to_vec()),
    ];
    let aggregate_pk = MentalPokerProtocol::compute_aggregate_key(&keys).unwrap();

    // Create initial deck
    let n = 8;
    let cards: Vec<Card> = (1..=n).map(|i| Card::from_index(i as u64)).collect();
    let mut deck: Vec<MaskedCard> = cards
        .iter()
        .map(|c| MentalPokerProtocol::mask(c, &aggregate_pk, None).unwrap().0)
        .collect();

    // Player 1 shuffles
    let perm1 = Permutation::random(n);
    let rand1: Vec<_> = (0..n).map(|_| scalar::random_felt()).collect();
    let (deck1, proof_1) =
        MentalPokerProtocol::shuffle_and_remask_with_proof(&deck, &aggregate_pk, &perm1, &rand1)
            .unwrap();

    // Verify player 1's shuffle
    assert!(
        MentalPokerProtocol::verify_shuffle(&deck, &deck1, &aggregate_pk, &proof_1).unwrap(),
        "Player 1's shuffle should verify"
    );

    // Player 2 shuffles
    let perm2 = Permutation::random(n);
    let rand2: Vec<_> = (0..n).map(|_| scalar::random_felt()).collect();
    let (deck2, proof_2) =
        MentalPokerProtocol::shuffle_and_remask_with_proof(&deck1, &aggregate_pk, &perm2, &rand2)
            .unwrap();

    // Verify player 2's shuffle
    assert!(
        MentalPokerProtocol::verify_shuffle(&deck1, &deck2, &aggregate_pk, &proof_2).unwrap(),
        "Player 2's shuffle should verify"
    );

    // Player 3 shuffles
    let perm3 = Permutation::random(n);
    let rand3: Vec<_> = (0..n).map(|_| scalar::random_felt()).collect();
    let (deck3, proof_3) =
        MentalPokerProtocol::shuffle_and_remask_with_proof(&deck2, &aggregate_pk, &perm3, &rand3)
            .unwrap();

    // Verify player 3's shuffle
    assert!(
        MentalPokerProtocol::verify_shuffle(&deck2, &deck3, &aggregate_pk, &proof_3).unwrap(),
        "Player 3's shuffle should verify"
    );

    // The final deck should still be decryptable
    // Take first card and have all players reveal
    let card_to_reveal = &deck3[0];

    let (token1, tproof1) =
        MentalPokerProtocol::compute_reveal_token(card_to_reveal, &sk1, &pk1).unwrap();
    let (token2, tproof2) =
        MentalPokerProtocol::compute_reveal_token(card_to_reveal, &sk2, &pk2).unwrap();
    let (token3, tproof3) =
        MentalPokerProtocol::compute_reveal_token(card_to_reveal, &sk3, &pk3).unwrap();

    let tokens = vec![
        (token1, tproof1, pk1),
        (token2, tproof2, pk2),
        (token3, tproof3, pk3),
    ];

    let revealed = MentalPokerProtocol::unmask(card_to_reveal, &tokens).unwrap();

    // The revealed card should be one of our original cards
    let original_points: Vec<_> = cards.iter().map(|c| c.point.clone()).collect();
    assert!(
        original_points.contains(&revealed.point),
        "Revealed card should be one of the original cards"
    );
}

/// Test batch verification of reveal tokens
#[test]
fn test_batch_reveal_verification() {
    use mental_poker::zkp::BatchVerifier;

    let (pk, sk) = MentalPokerProtocol::player_keygen();

    // Create multiple masked cards
    let cards: Vec<Card> = (1..=5).map(|i| Card::from_index(i as u64)).collect();
    let masked_cards: Vec<MaskedCard> = cards
        .iter()
        .map(|c| MentalPokerProtocol::mask(c, &pk, None).unwrap().0)
        .collect();

    // Compute reveal tokens for all
    let mut proofs = Vec::new();
    for masked in &masked_cards {
        let (token, proof) = MentalPokerProtocol::compute_reveal_token(masked, &sk, &pk).unwrap();
        proofs.push((masked.clone(), token, pk.clone(), proof));
    }

    // Batch verify
    let valid = BatchVerifier::verify_reveal_tokens_batch(&proofs).unwrap();
    assert!(valid, "Batch verification should pass for valid proofs");
}
