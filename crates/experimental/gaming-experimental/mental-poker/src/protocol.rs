//! Mental Poker Protocol Implementation
//!
//! This module implements the Barnett-Smart mental poker protocol with
//! discrete-log based card operations on the Stark curve.

use crate::error::{MentalPokerError, Result};
use crate::types::*;
use crate::zkp::{ChaumPedersenProtocol, SchnorrProtocol};
use krusty_kms_crypto::{scalar, StarkCurve};
use starknet_types_core::felt::Felt;

/// Context bytes for different proof types
pub(crate) const KEY_OWNERSHIP_CONTEXT: &[u8] = b"mental-poker-key-ownership";
pub(crate) const MASKING_CONTEXT: &[u8] = b"mental-poker-masking";
pub(crate) const REMASKING_CONTEXT: &[u8] = b"mental-poker-remasking";
pub(crate) const REVEAL_CONTEXT: &[u8] = b"mental-poker-reveal";

/// The Mental Poker Protocol implementation.
///
/// This provides all the cryptographic operations needed for a mental poker game:
/// - Key generation and aggregation
/// - Card masking and remasking
/// - Reveal token computation
/// - Deck shuffling (with proofs)
pub struct MentalPokerProtocol;

impl MentalPokerProtocol {
    /// Setup protocol parameters.
    ///
    /// # Arguments
    /// * `m` - Number of rows in deck matrix
    /// * `n` - Number of columns in deck matrix
    pub fn setup(m: usize, n: usize) -> Result<Parameters> {
        if m == 0 || n == 0 {
            return Err(MentalPokerError::InvalidParameters(
                "m and n must be positive".to_string(),
            ));
        }
        Ok(Parameters::new(m, n))
    }

    /// Generate a key pair for a player.
    pub fn player_keygen() -> (PublicKey, SecretKey) {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        (pk, sk)
    }

    /// Prove ownership of a key pair.
    ///
    /// # Arguments
    /// * `pk` - The public key
    /// * `sk` - The secret key
    /// * `player_info` - Additional context (e.g., player name)
    pub fn prove_key_ownership(
        pk: &PublicKey,
        sk: &SecretKey,
        player_info: &[u8],
    ) -> Result<KeyOwnershipProof> {
        let mut context = Vec::from(KEY_OWNERSHIP_CONTEXT);
        context.extend_from_slice(player_info);
        SchnorrProtocol::prove(pk, sk, &context)
    }

    /// Verify a key ownership proof.
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid, `Ok(false)` if invalid,
    /// or an error if verification could not be performed.
    #[must_use = "verification result must be checked"]
    pub fn verify_key_ownership(
        pk: &PublicKey,
        proof: &KeyOwnershipProof,
        player_info: &[u8],
    ) -> Result<bool> {
        let mut context = Vec::from(KEY_OWNERSHIP_CONTEXT);
        context.extend_from_slice(player_info);
        SchnorrProtocol::verify(pk, proof, &context)
    }

    /// Compute the aggregate public key from all players' keys.
    ///
    /// Each player's key ownership must be verified first.
    pub fn compute_aggregate_key(
        player_keys: &[(PublicKey, KeyOwnershipProof, Vec<u8>)],
    ) -> Result<PublicKey> {
        let mut aggregate = PublicKey::zero();

        for (pk, proof, player_info) in player_keys {
            if !Self::verify_key_ownership(pk, proof, player_info)? {
                return Err(MentalPokerError::InvalidKeyOwnership);
            }
            aggregate = aggregate.add(pk);
        }

        Ok(aggregate)
    }

    /// Mask an open card using the aggregate public key.
    ///
    /// This is ElGamal encryption: (g^r, card + pk^r)
    ///
    /// # Arguments
    /// * `card` - The open card to mask
    /// * `aggregate_pk` - The aggregate public key
    /// * `r` - Random masking factor (optional, generated if None)
    ///
    /// # Returns
    /// The masked card and a proof of correct masking
    pub fn mask(
        card: &Card,
        aggregate_pk: &PublicKey,
        r: Option<&Felt>,
    ) -> Result<(MaskedCard, DLEqualityProof)> {
        let g = StarkCurve::GENERATOR;
        let r_val = r.cloned().unwrap_or_else(scalar::random_felt);

        // Compute ciphertext: c0 = g^r, c1 = card + pk^r
        let c0 = StarkCurve::mul(&r_val, Some(&g));
        let pk_r = StarkCurve::mul(&r_val, Some(&aggregate_pk.point));
        let c1 = StarkCurve::add(&card.point, &pk_r);

        let masked = MaskedCard::new(c0.clone(), c1.clone());

        // Prove: log_g(c0) = log_pk(c1 - card)
        // i.e., we correctly encrypted with randomness r
        let neg_card = crate::utils::negate_point(&card.point)?;
        let c1_minus_card = StarkCurve::add(&c1, &neg_card);

        let proof = ChaumPedersenProtocol::prove(
            &g,
            &aggregate_pk.point,
            &c0,
            &c1_minus_card,
            &r_val,
            MASKING_CONTEXT,
        )?;

        Ok((masked, proof))
    }

    /// Verify a masking proof.
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid, `Ok(false)` if invalid.
    #[must_use = "verification result must be checked"]
    pub fn verify_mask(
        card: &Card,
        masked: &MaskedCard,
        aggregate_pk: &PublicKey,
        proof: &DLEqualityProof,
    ) -> Result<bool> {
        let g = StarkCurve::GENERATOR;

        // Compute c1 - card
        let neg_card = crate::utils::negate_point(&card.point)?;
        let c1_minus_card = StarkCurve::add(&masked.c1, &neg_card);

        ChaumPedersenProtocol::verify(
            &g,
            &aggregate_pk.point,
            &masked.c0,
            &c1_minus_card,
            proof,
            MASKING_CONTEXT,
        )
    }

    /// Remask a masked card (re-randomize the encryption).
    ///
    /// This adds a fresh encryption of zero to the ciphertext.
    pub fn remask(
        masked: &MaskedCard,
        aggregate_pk: &PublicKey,
        alpha: Option<&Felt>,
    ) -> Result<(MaskedCard, DLEqualityProof)> {
        let g = StarkCurve::GENERATOR;
        let alpha_val = alpha.cloned().unwrap_or_else(scalar::random_felt);

        // Encrypt zero: (g^alpha, pk^alpha)
        let zero_c0 = StarkCurve::mul(&alpha_val, Some(&g));
        let zero_c1 = StarkCurve::mul(&alpha_val, Some(&aggregate_pk.point));

        // Add to existing ciphertext
        let new_c0 = StarkCurve::add(&masked.c0, &zero_c0);
        let new_c1 = StarkCurve::add(&masked.c1, &zero_c1);
        let remasked = MaskedCard::new(new_c0, new_c1);

        // Compute difference for proof
        let diff = remasked.add(&masked.negate()?);

        // Prove: log_g(diff.c0) = log_pk(diff.c1)
        let proof = ChaumPedersenProtocol::prove(
            &g,
            &aggregate_pk.point,
            &diff.c0,
            &diff.c1,
            &alpha_val,
            REMASKING_CONTEXT,
        )?;

        Ok((remasked, proof))
    }

    /// Verify a remasking proof.
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid, `Ok(false)` if invalid.
    #[must_use = "verification result must be checked"]
    pub fn verify_remask(
        original: &MaskedCard,
        remasked: &MaskedCard,
        aggregate_pk: &PublicKey,
        proof: &DLEqualityProof,
    ) -> Result<bool> {
        let g = StarkCurve::GENERATOR;

        // Compute difference
        let diff = remasked.add(&original.negate()?);

        ChaumPedersenProtocol::verify(
            &g,
            &aggregate_pk.point,
            &diff.c0,
            &diff.c1,
            proof,
            REMASKING_CONTEXT,
        )
    }

    /// Compute a reveal token for a masked card.
    ///
    /// The reveal token is: token = c0^sk
    pub fn compute_reveal_token(
        masked: &MaskedCard,
        sk: &SecretKey,
        pk: &PublicKey,
    ) -> Result<(RevealToken, DLEqualityProof)> {
        let g = StarkCurve::GENERATOR;

        // Compute token = c0^sk
        let token_point = StarkCurve::mul(&sk.scalar, Some(&masked.c0));
        let token = RevealToken::new(token_point);

        // Prove: log_c0(token) = log_g(pk)
        // i.e., we used the correct secret key
        let proof = ChaumPedersenProtocol::prove(
            &masked.c0,
            &g,
            &token.point,
            &pk.point,
            &sk.scalar,
            REVEAL_CONTEXT,
        )?;

        Ok((token, proof))
    }

    /// Verify a reveal token proof.
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid, `Ok(false)` if invalid.
    #[must_use = "verification result must be checked"]
    pub fn verify_reveal_token(
        masked: &MaskedCard,
        token: &RevealToken,
        pk: &PublicKey,
        proof: &DLEqualityProof,
    ) -> Result<bool> {
        let g = StarkCurve::GENERATOR;

        ChaumPedersenProtocol::verify(
            &masked.c0,
            &g,
            &token.point,
            &pk.point,
            proof,
            REVEAL_CONTEXT,
        )
    }

    /// Unmask a card using all reveal tokens.
    ///
    /// Each reveal token and proof must be verified first.
    pub fn unmask(
        masked: &MaskedCard,
        reveal_tokens: &[(RevealToken, DLEqualityProof, PublicKey)],
    ) -> Result<Card> {
        // Aggregate all reveal tokens
        let mut aggregate_token = RevealToken::zero();

        for (token, proof, pk) in reveal_tokens {
            if !Self::verify_reveal_token(masked, token, pk, proof)? {
                return Err(MentalPokerError::InvalidRevealProof);
            }
            aggregate_token = aggregate_token.add(token);
        }

        // Decrypt: card = c1 - aggregate_token
        let neg_token = crate::utils::negate_point(&aggregate_token.point)?;
        let card_point = StarkCurve::add(&masked.c1, &neg_token);

        Ok(Card::new(card_point))
    }

    /// Shuffle and remask a deck of cards (without ZK proof).
    ///
    /// Applies a permutation and remasking to each card.
    ///
    /// # Security Warning
    ///
    /// This version does NOT include a zero-knowledge shuffle proof.
    /// Use `shuffle_and_remask_with_proof` for adversarial settings.
    ///
    /// **Use only in trusted environments or for demonstration purposes.**
    pub fn shuffle_and_remask(
        deck: &[MaskedCard],
        aggregate_pk: &PublicKey,
        permutation: &Permutation,
        masking_factors: &[Felt],
    ) -> Result<Vec<(MaskedCard, DLEqualityProof)>> {
        if deck.len() != permutation.len() || deck.len() != masking_factors.len() {
            return Err(MentalPokerError::InvalidParameters(
                "Deck, permutation, and masking factors must have same length".to_string(),
            ));
        }

        // Apply permutation
        let permuted = permutation.permute(deck);

        // Remask each card
        permuted
            .iter()
            .zip(masking_factors.iter())
            .map(|(card, factor)| Self::remask(card, aggregate_pk, Some(factor)))
            .collect()
    }

    /// Shuffle and remask a deck of cards with a zero-knowledge proof.
    ///
    /// This is the secure version that produces a Bayer-Groth style shuffle argument
    /// proving the shuffle was performed correctly without revealing the permutation.
    ///
    /// # Arguments
    /// * `deck` - The input deck of masked cards
    /// * `aggregate_pk` - The aggregate public key for re-encryption
    /// * `permutation` - The secret permutation to apply
    /// * `masking_factors` - Random factors for re-encryption
    ///
    /// # Returns
    /// A tuple of (shuffled deck, shuffle proof)
    pub fn shuffle_and_remask_with_proof(
        deck: &[MaskedCard],
        aggregate_pk: &PublicKey,
        permutation: &Permutation,
        masking_factors: &[Felt],
    ) -> Result<(Vec<MaskedCard>, crate::shuffle::ShuffleProof)> {
        use crate::shuffle::{
            ShuffleArgument, ShuffleParameters, ShuffleStatement, ShuffleWitness,
        };

        if deck.len() != permutation.len() || deck.len() != masking_factors.len() {
            return Err(MentalPokerError::InvalidParameters(
                "Deck, permutation, and masking factors must have same length".to_string(),
            ));
        }

        let n = deck.len();

        // Apply permutation
        let permuted = permutation.permute(deck);

        // Apply remasking (re-encryption with fresh randomness)
        let output_deck: Vec<MaskedCard> = permuted
            .iter()
            .zip(masking_factors.iter())
            .map(|(card, r)| {
                // Encrypt zero: (g^r, pk^r)
                let zero_c0 = StarkCurve::mul_generator(r);
                let zero_c1 = StarkCurve::mul(r, Some(&aggregate_pk.point));
                // Add to existing ciphertext
                MaskedCard::new(
                    StarkCurve::add(&card.c0, &zero_c0),
                    StarkCurve::add(&card.c1, &zero_c1),
                )
            })
            .collect();

        // Generate shuffle parameters
        let params = ShuffleParameters::new(n)?;

        // Create statement and witness
        let statement =
            ShuffleStatement::new(deck.to_vec(), output_deck.clone(), aggregate_pk.clone())?;
        let witness = ShuffleWitness::new(permutation.clone(), masking_factors.to_vec())?;

        // Generate proof
        let proof = ShuffleArgument::prove(&params, &statement, &witness)?;

        Ok((output_deck, proof))
    }

    /// Verify a shuffle proof.
    ///
    /// Verifies that a shuffled deck is a valid permutation and re-encryption
    /// of the original deck.
    ///
    /// # Arguments
    /// * `original_deck` - The original (input) deck
    /// * `shuffled_deck` - The shuffled (output) deck
    /// * `aggregate_pk` - The aggregate public key
    /// * `proof` - The shuffle proof to verify
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid, `Ok(false)` otherwise.
    #[must_use = "verification result must be checked"]
    pub fn verify_shuffle(
        original_deck: &[MaskedCard],
        shuffled_deck: &[MaskedCard],
        aggregate_pk: &PublicKey,
        proof: &crate::shuffle::ShuffleProof,
    ) -> Result<bool> {
        use crate::shuffle::{ShuffleArgument, ShuffleParameters, ShuffleStatement};

        if original_deck.len() != shuffled_deck.len() {
            return Ok(false);
        }

        let n = original_deck.len();
        let params = ShuffleParameters::new(n)?;
        let statement = ShuffleStatement::new(
            original_deck.to_vec(),
            shuffled_deck.to_vec(),
            aggregate_pk.clone(),
        )?;

        ShuffleArgument::verify(&params, &statement, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup() {
        let params = MentalPokerProtocol::setup(4, 13).unwrap();
        assert_eq!(params.num_cards, 52);
    }

    #[test]
    fn test_key_ownership() {
        let (pk, sk) = MentalPokerProtocol::player_keygen();
        let player_info = b"Alice";

        let proof = MentalPokerProtocol::prove_key_ownership(&pk, &sk, player_info).unwrap();
        let valid = MentalPokerProtocol::verify_key_ownership(&pk, &proof, player_info).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_aggregate_key() {
        let (pk1, sk1) = MentalPokerProtocol::player_keygen();
        let (pk2, sk2) = MentalPokerProtocol::player_keygen();

        let proof1 = MentalPokerProtocol::prove_key_ownership(&pk1, &sk1, b"Alice").unwrap();
        let proof2 = MentalPokerProtocol::prove_key_ownership(&pk2, &sk2, b"Bob").unwrap();

        let keys = vec![
            (pk1, proof1, b"Alice".to_vec()),
            (pk2, proof2, b"Bob".to_vec()),
        ];

        let aggregate = MentalPokerProtocol::compute_aggregate_key(&keys).unwrap();
        assert!(!StarkCurve::is_infinity(&aggregate.point));
    }

    #[test]
    fn test_mask_and_verify() {
        let (pk, _sk) = MentalPokerProtocol::player_keygen();
        let card = Card::from_index(1);

        let (masked, proof) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();
        let valid = MentalPokerProtocol::verify_mask(&card, &masked, &pk, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_remask_and_verify() {
        let (pk, _sk) = MentalPokerProtocol::player_keygen();
        let card = Card::from_index(1);

        let (masked, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();
        let (remasked, proof) = MentalPokerProtocol::remask(&masked, &pk, None).unwrap();
        let valid = MentalPokerProtocol::verify_remask(&masked, &remasked, &pk, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_reveal_and_unmask() {
        let (pk1, sk1) = MentalPokerProtocol::player_keygen();
        let (pk2, sk2) = MentalPokerProtocol::player_keygen();
        let aggregate_pk = pk1.add(&pk2);

        let card = Card::from_index(42);
        let (masked, _) = MentalPokerProtocol::mask(&card, &aggregate_pk, None).unwrap();

        // Both players compute reveal tokens
        let (token1, proof1) =
            MentalPokerProtocol::compute_reveal_token(&masked, &sk1, &pk1).unwrap();
        let (token2, proof2) =
            MentalPokerProtocol::compute_reveal_token(&masked, &sk2, &pk2).unwrap();

        // Unmask the card
        let tokens = vec![(token1, proof1, pk1), (token2, proof2, pk2)];
        let revealed = MentalPokerProtocol::unmask(&masked, &tokens).unwrap();

        // The revealed card should match the original
        let revealed_affine = StarkCurve::projective_to_affine(&revealed.point).unwrap();
        let original_affine = StarkCurve::projective_to_affine(&card.point).unwrap();
        assert_eq!(revealed_affine, original_affine);
    }

    #[test]
    fn test_full_protocol_flow() {
        // Setup
        let _params = MentalPokerProtocol::setup(4, 13).unwrap();

        // Two players
        let (pk1, sk1) = MentalPokerProtocol::player_keygen();
        let (pk2, sk2) = MentalPokerProtocol::player_keygen();

        // Key ownership proofs
        let proof1 = MentalPokerProtocol::prove_key_ownership(&pk1, &sk1, b"Alice").unwrap();
        let proof2 = MentalPokerProtocol::prove_key_ownership(&pk2, &sk2, b"Bob").unwrap();

        // Aggregate key (clone pks since we need them later)
        let keys = vec![
            (pk1.clone(), proof1, b"Alice".to_vec()),
            (pk2.clone(), proof2, b"Bob".to_vec()),
        ];
        let aggregate_pk = MentalPokerProtocol::compute_aggregate_key(&keys).unwrap();

        // Create a small deck (3 cards) - start from 1 to avoid identity point
        let cards: Vec<Card> = (1..4).map(Card::from_index).collect();

        // Mask all cards
        let masked_deck: Vec<(MaskedCard, DLEqualityProof)> = cards
            .iter()
            .map(|c| MentalPokerProtocol::mask(c, &aggregate_pk, None).unwrap())
            .collect();

        // Player 1 shuffles
        let perm = Permutation::random(3);
        let factors: Vec<Felt> = (0..3).map(|_| scalar::random_felt()).collect();
        let deck_only: Vec<MaskedCard> = masked_deck.iter().map(|(m, _)| m.clone()).collect();
        let shuffled =
            MentalPokerProtocol::shuffle_and_remask(&deck_only, &aggregate_pk, &perm, &factors)
                .unwrap();

        // Take one card and reveal it
        let (card_to_reveal, _) = &shuffled[0];

        let (token1, proof1) =
            MentalPokerProtocol::compute_reveal_token(card_to_reveal, &sk1, &pk1).unwrap();
        let (token2, proof2) =
            MentalPokerProtocol::compute_reveal_token(card_to_reveal, &sk2, &pk2).unwrap();

        let tokens = vec![(token1, proof1, pk1), (token2, proof2, pk2)];
        let revealed = MentalPokerProtocol::unmask(card_to_reveal, &tokens).unwrap();

        // The revealed card should be one of our original cards (permuted)
        // We can't easily verify which one without tracking the permutation
        assert!(!StarkCurve::is_infinity(&revealed.point));
    }
}
