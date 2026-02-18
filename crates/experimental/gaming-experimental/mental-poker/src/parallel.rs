//! Parallel processing utilities for mental poker operations.
//!
//! This module provides parallelized versions of computationally intensive
//! operations using rayon for improved performance on multi-core systems.
//!
//! # Feature Flag
//!
//! These functions are only available when the `parallel` feature is enabled
//! (which is on by default).

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::error::Result;
use crate::protocol::MentalPokerProtocol;
use crate::types::{Card, DLEqualityProof, MaskedCard, PublicKey, RevealToken, SecretKey};

/// Parallel batch operations for mental poker.
pub struct ParallelOps;

impl ParallelOps {
    /// Mask multiple cards in parallel.
    ///
    /// This is significantly faster than sequential masking for large decks.
    ///
    /// # Arguments
    /// * `cards` - The open cards to mask
    /// * `aggregate_pk` - The aggregate public key
    ///
    /// # Returns
    /// Vector of (masked_card, proof) tuples
    #[cfg(feature = "parallel")]
    pub fn mask_cards_parallel(
        cards: &[Card],
        aggregate_pk: &PublicKey,
    ) -> Result<Vec<(MaskedCard, DLEqualityProof)>> {
        cards
            .par_iter()
            .map(|card| MentalPokerProtocol::mask(card, aggregate_pk, None))
            .collect()
    }

    /// Mask multiple cards sequentially (fallback when parallel feature disabled).
    #[cfg(not(feature = "parallel"))]
    pub fn mask_cards_parallel(
        cards: &[Card],
        aggregate_pk: &PublicKey,
    ) -> Result<Vec<(MaskedCard, DLEqualityProof)>> {
        cards
            .iter()
            .map(|card| MentalPokerProtocol::mask(card, aggregate_pk, None))
            .collect()
    }

    /// Compute reveal tokens for multiple cards in parallel.
    ///
    /// Useful when a player needs to reveal multiple cards at once.
    ///
    /// # Arguments
    /// * `masked_cards` - The masked cards to compute tokens for
    /// * `sk` - The player's secret key
    /// * `pk` - The player's public key
    ///
    /// # Returns
    /// Vector of (reveal_token, proof) tuples
    #[cfg(feature = "parallel")]
    pub fn compute_reveal_tokens_parallel(
        masked_cards: &[MaskedCard],
        sk: &SecretKey,
        pk: &PublicKey,
    ) -> Result<Vec<(RevealToken, DLEqualityProof)>> {
        masked_cards
            .par_iter()
            .map(|card| MentalPokerProtocol::compute_reveal_token(card, sk, pk))
            .collect()
    }

    /// Compute reveal tokens sequentially (fallback).
    #[cfg(not(feature = "parallel"))]
    pub fn compute_reveal_tokens_parallel(
        masked_cards: &[MaskedCard],
        sk: &SecretKey,
        pk: &PublicKey,
    ) -> Result<Vec<(RevealToken, DLEqualityProof)>> {
        masked_cards
            .iter()
            .map(|card| MentalPokerProtocol::compute_reveal_token(card, sk, pk))
            .collect()
    }

    /// Verify multiple mask proofs in parallel.
    ///
    /// # Returns
    /// `Ok(true)` if all proofs are valid, `Ok(false)` if any is invalid.
    #[cfg(feature = "parallel")]
    pub fn verify_masks_parallel(
        cards: &[Card],
        masked_cards: &[MaskedCard],
        aggregate_pk: &PublicKey,
        proofs: &[DLEqualityProof],
    ) -> Result<bool> {
        if cards.len() != masked_cards.len() || cards.len() != proofs.len() {
            return Ok(false);
        }

        let results: Result<Vec<bool>> = cards
            .par_iter()
            .zip(masked_cards.par_iter())
            .zip(proofs.par_iter())
            .map(|((card, masked), proof)| {
                MentalPokerProtocol::verify_mask(card, masked, aggregate_pk, proof)
            })
            .collect();

        Ok(results?.into_iter().all(|v| v))
    }

    /// Verify mask proofs sequentially (fallback).
    #[cfg(not(feature = "parallel"))]
    pub fn verify_masks_parallel(
        cards: &[Card],
        masked_cards: &[MaskedCard],
        aggregate_pk: &PublicKey,
        proofs: &[DLEqualityProof],
    ) -> Result<bool> {
        if cards.len() != masked_cards.len() || cards.len() != proofs.len() {
            return Ok(false);
        }

        for ((card, masked), proof) in cards.iter().zip(masked_cards.iter()).zip(proofs.iter()) {
            if !MentalPokerProtocol::verify_mask(card, masked, aggregate_pk, proof)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Verify multiple reveal token proofs in parallel.
    ///
    /// # Returns
    /// `Ok(true)` if all proofs are valid, `Ok(false)` if any is invalid.
    #[cfg(feature = "parallel")]
    pub fn verify_reveal_tokens_parallel(
        masked_cards: &[MaskedCard],
        tokens: &[RevealToken],
        pks: &[PublicKey],
        proofs: &[DLEqualityProof],
    ) -> Result<bool> {
        if masked_cards.len() != tokens.len()
            || masked_cards.len() != pks.len()
            || masked_cards.len() != proofs.len()
        {
            return Ok(false);
        }

        let results: Result<Vec<bool>> = masked_cards
            .par_iter()
            .zip(tokens.par_iter())
            .zip(pks.par_iter())
            .zip(proofs.par_iter())
            .map(|(((masked, token), pk), proof)| {
                MentalPokerProtocol::verify_reveal_token(masked, token, pk, proof)
            })
            .collect();

        Ok(results?.into_iter().all(|v| v))
    }

    /// Verify reveal tokens sequentially (fallback).
    #[cfg(not(feature = "parallel"))]
    pub fn verify_reveal_tokens_parallel(
        masked_cards: &[MaskedCard],
        tokens: &[RevealToken],
        pks: &[PublicKey],
        proofs: &[DLEqualityProof],
    ) -> Result<bool> {
        if masked_cards.len() != tokens.len()
            || masked_cards.len() != pks.len()
            || masked_cards.len() != proofs.len()
        {
            return Ok(false);
        }

        for (((masked, token), pk), proof) in masked_cards
            .iter()
            .zip(tokens.iter())
            .zip(pks.iter())
            .zip(proofs.iter())
        {
            if !MentalPokerProtocol::verify_reveal_token(masked, token, pk, proof)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Card;

    #[test]
    fn test_parallel_mask_cards() {
        let (pk, _sk) = MentalPokerProtocol::player_keygen();
        let cards: Vec<Card> = (1..=10).map(|i| Card::from_index(i)).collect();

        let results = ParallelOps::mask_cards_parallel(&cards, &pk).unwrap();
        assert_eq!(results.len(), 10);

        // Verify all proofs are valid
        for (i, (masked, proof)) in results.iter().enumerate() {
            let valid = MentalPokerProtocol::verify_mask(&cards[i], masked, &pk, proof).unwrap();
            assert!(valid);
        }
    }

    #[test]
    fn test_parallel_reveal_tokens() {
        let (pk, sk) = MentalPokerProtocol::player_keygen();
        let cards: Vec<Card> = (1..=5).map(|i| Card::from_index(i)).collect();

        let masked: Vec<MaskedCard> = cards
            .iter()
            .map(|c| MentalPokerProtocol::mask(c, &pk, None).unwrap().0)
            .collect();

        let results = ParallelOps::compute_reveal_tokens_parallel(&masked, &sk, &pk).unwrap();
        assert_eq!(results.len(), 5);

        // Verify all tokens are valid
        for (i, (token, proof)) in results.iter().enumerate() {
            let valid =
                MentalPokerProtocol::verify_reveal_token(&masked[i], token, &pk, proof).unwrap();
            assert!(valid);
        }
    }

    #[test]
    fn test_parallel_verify_masks() {
        let (pk, _sk) = MentalPokerProtocol::player_keygen();
        let cards: Vec<Card> = (1..=8).map(|i| Card::from_index(i)).collect();

        let results = ParallelOps::mask_cards_parallel(&cards, &pk).unwrap();
        let (masked_cards, proofs): (Vec<_>, Vec<_>) = results.into_iter().unzip();

        let valid =
            ParallelOps::verify_masks_parallel(&cards, &masked_cards, &pk, &proofs).unwrap();
        assert!(valid);
    }
}
