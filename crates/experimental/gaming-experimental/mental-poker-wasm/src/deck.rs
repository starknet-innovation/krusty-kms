//! Deck management for mental poker.
//!
//! Handles deck creation, shuffling, masking, and card operations.

use crate::error::WasmMentalPokerError;
use crate::types::{WasmCard, WasmDLEqualityProof, WasmPoint, WasmPublicKey};
use mental_poker::types::{Card, MaskedCard, Permutation, PublicKey};
use mental_poker::MentalPokerProtocol;
use serde::{Deserialize, Serialize};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

/// A masked (encrypted) card.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmMaskedCard {
    /// First component (g^r)
    pub c0_x: String,
    pub c0_y: String,
    /// Second component (card + pk^r)
    pub c1_x: String,
    pub c1_y: String,
}

#[wasm_bindgen]
impl WasmMaskedCard {
    #[wasm_bindgen(constructor)]
    pub fn new(c0_x: String, c0_y: String, c1_x: String, c1_y: String) -> Self {
        Self {
            c0_x,
            c0_y,
            c1_x,
            c1_y,
        }
    }

    /// Convert to compact binary format (128 bytes).
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        let c0_x = Felt::from_hex(&self.c0_x)
            .map_err(|e| JsValue::from_str(&format!("Invalid c0_x: {e}")))?;
        let c0_y = Felt::from_hex(&self.c0_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid c0_y: {e}")))?;
        let c1_x = Felt::from_hex(&self.c1_x)
            .map_err(|e| JsValue::from_str(&format!("Invalid c1_x: {e}")))?;
        let c1_y = Felt::from_hex(&self.c1_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid c1_y: {e}")))?;

        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(&c0_x.to_bytes_be());
        bytes.extend_from_slice(&c0_y.to_bytes_be());
        bytes.extend_from_slice(&c1_x.to_bytes_be());
        bytes.extend_from_slice(&c1_y.to_bytes_be());
        Ok(bytes)
    }

    /// Create from compact binary format (128 bytes).
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmMaskedCard, JsValue> {
        if bytes.len() != 128 {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length: expected 128 bytes, got {}",
                bytes.len()
            )));
        }

        let c0_x = Felt::from_bytes_be(
            bytes[0..32]
                .try_into()
                .map_err(|_| JsValue::from_str("Failed to parse c0_x: invalid byte slice"))?,
        );
        let c0_y = Felt::from_bytes_be(
            bytes[32..64]
                .try_into()
                .map_err(|_| JsValue::from_str("Failed to parse c0_y: invalid byte slice"))?,
        );
        let c1_x = Felt::from_bytes_be(
            bytes[64..96]
                .try_into()
                .map_err(|_| JsValue::from_str("Failed to parse c1_x: invalid byte slice"))?,
        );
        let c1_y = Felt::from_bytes_be(
            bytes[96..128]
                .try_into()
                .map_err(|_| JsValue::from_str("Failed to parse c1_y: invalid byte slice"))?,
        );

        Ok(WasmMaskedCard {
            c0_x: format!("{:#x}", c0_x),
            c0_y: format!("{:#x}", c0_y),
            c1_x: format!("{:#x}", c1_x),
            c1_y: format!("{:#x}", c1_y),
        })
    }
}

impl WasmMaskedCard {
    fn to_native(&self) -> Result<MaskedCard, WasmMentalPokerError> {
        let c0_x = Felt::from_hex(&self.c0_x)
            .map_err(|e| WasmMentalPokerError::InvalidInput(format!("Invalid c0_x: {e}")))?;
        let c0_y = Felt::from_hex(&self.c0_y)
            .map_err(|e| WasmMentalPokerError::InvalidInput(format!("Invalid c0_y: {e}")))?;
        let c1_x = Felt::from_hex(&self.c1_x)
            .map_err(|e| WasmMentalPokerError::InvalidInput(format!("Invalid c1_x: {e}")))?;
        let c1_y = Felt::from_hex(&self.c1_y)
            .map_err(|e| WasmMentalPokerError::InvalidInput(format!("Invalid c1_y: {e}")))?;

        let c0 = ProjectivePoint::from_affine(c0_x, c0_y)
            .map_err(|_| WasmMentalPokerError::InvalidInput("Invalid c0 point".to_string()))?;
        let c1 = ProjectivePoint::from_affine(c1_x, c1_y)
            .map_err(|_| WasmMentalPokerError::InvalidInput("Invalid c1 point".to_string()))?;

        Ok(MaskedCard::new(c0, c1))
    }

    fn from_native(masked: &MaskedCard) -> Result<Self, WasmMentalPokerError> {
        let c0_affine = masked
            .c0
            .to_affine()
            .map_err(|_| WasmMentalPokerError::CryptoError("Invalid c0 point".to_string()))?;
        let c1_affine = masked
            .c1
            .to_affine()
            .map_err(|_| WasmMentalPokerError::CryptoError("Invalid c1 point".to_string()))?;

        Ok(WasmMaskedCard {
            c0_x: format!("{:#x}", c0_affine.x()),
            c0_y: format!("{:#x}", c0_affine.y()),
            c1_x: format!("{:#x}", c1_affine.x()),
            c1_y: format!("{:#x}", c1_affine.y()),
        })
    }
}

/// Result of masking a card.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmMaskResult {
    pub masked_card: WasmMaskedCard,
    pub proof: WasmDLEqualityProof,
}

/// Result of shuffling a deck with proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmShuffleProofResult {
    /// The shuffled deck
    pub deck: Vec<WasmMaskedCard>,
    /// Proof of correct shuffle (JSON string)
    pub proof_json: String,
}

/// A masked deck of cards.
#[wasm_bindgen]
pub struct WasmMaskedDeck {
    cards: Vec<MaskedCard>,
}

#[wasm_bindgen]
impl WasmMaskedDeck {
    /// Get the number of cards in the deck.
    #[wasm_bindgen(js_name = "length")]
    pub fn len(&self) -> usize {
        self.cards.len()
    }

    /// Check if deck is empty.
    #[wasm_bindgen(js_name = "isEmpty")]
    pub fn is_empty(&self) -> bool {
        self.cards.is_empty()
    }

    /// Get a card at a specific index.
    #[wasm_bindgen(js_name = "getCard")]
    pub fn get_card(&self, index: usize) -> Result<WasmMaskedCard, JsValue> {
        let card = self
            .cards
            .get(index)
            .ok_or_else(|| JsValue::from_str("Index out of bounds"))?;
        WasmMaskedCard::from_native(card).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Get all cards as an array.
    #[wasm_bindgen(js_name = "getAllCards")]
    pub fn get_all_cards(&self) -> Result<Vec<WasmMaskedCard>, JsValue> {
        self.cards
            .iter()
            .map(|c| WasmMaskedCard::from_native(c).map_err(|e| JsValue::from_str(&e.to_string())))
            .collect()
    }

    /// Shuffle the deck with a random permutation and generate proof.
    #[wasm_bindgen(js_name = "shuffleWithProof")]
    pub fn shuffle_with_proof(
        &self,
        aggregate_pk_x: &str,
        aggregate_pk_y: &str,
    ) -> Result<WasmShuffleProofResult, JsValue> {
        let pk = parse_public_key(aggregate_pk_x, aggregate_pk_y)?;

        // Generate random permutation
        let n = self.cards.len();
        let permutation = Permutation::random(n);

        // Generate random masking factors
        let masking_factors: Vec<Felt> = (0..n)
            .map(|_| krusty_kms_crypto::scalar::random_felt())
            .collect();

        // Shuffle with proof
        let (shuffled, proof) = MentalPokerProtocol::shuffle_and_remask_with_proof(
            &self.cards,
            &pk,
            &permutation,
            &masking_factors,
        )
        .map_err(|e| JsValue::from_str(&format!("Shuffle failed: {e}")))?;

        // Convert shuffled cards
        let wasm_cards: Vec<WasmMaskedCard> = shuffled
            .iter()
            .map(|c| WasmMaskedCard::from_native(c).map_err(|e| JsValue::from_str(&e.to_string())))
            .collect::<Result<_, _>>()?;

        // Serialize proof to JSON
        let proof_json = serde_json::to_string(&proof)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize proof: {e}")))?;

        Ok(WasmShuffleProofResult {
            deck: wasm_cards,
            proof_json,
        })
    }

    /// Create a WasmMaskedDeck from an array of masked cards.
    #[wasm_bindgen(js_name = "fromCards")]
    pub fn from_cards(cards: Vec<WasmMaskedCard>) -> Result<WasmMaskedDeck, JsValue> {
        let native_cards: Vec<MaskedCard> = cards
            .iter()
            .map(|c| c.to_native().map_err(|e| JsValue::from_str(&e.to_string())))
            .collect::<Result<_, _>>()?;

        Ok(WasmMaskedDeck {
            cards: native_cards,
        })
    }
}

/// An open deck of cards (before masking).
#[wasm_bindgen]
pub struct WasmDeck {
    cards: Vec<Card>,
}

impl WasmDeck {
    /// Create a WasmDeck from a vector of native Card objects.
    /// This is used internally by modules like crossy that need custom card layouts.
    pub(crate) fn from_cards_internal(cards: Vec<Card>) -> Self {
        Self { cards }
    }
}

#[wasm_bindgen]
impl WasmDeck {
    /// Get the number of cards in the deck.
    #[wasm_bindgen(js_name = "length")]
    pub fn len(&self) -> usize {
        self.cards.len()
    }

    /// Check if deck is empty.
    #[wasm_bindgen(js_name = "isEmpty")]
    pub fn is_empty(&self) -> bool {
        self.cards.is_empty()
    }

    /// Get a card at a specific index.
    #[wasm_bindgen(js_name = "getCard")]
    pub fn get_card(&self, index: usize) -> Result<WasmCard, JsValue> {
        let card = self
            .cards
            .get(index)
            .ok_or_else(|| JsValue::from_str("Index out of bounds"))?;
        let affine = card
            .point
            .to_affine()
            .map_err(|_| JsValue::from_str("Invalid card point"))?;

        Ok(WasmCard {
            index: (index + 1) as u64, // 1-indexed
            point: WasmPoint {
                x: format!("{:#x}", affine.x()),
                y: format!("{:#x}", affine.y()),
            },
        })
    }

    /// Mask all cards in the deck with the aggregate public key.
    ///
    /// Returns a masked deck with proofs for each card.
    #[wasm_bindgen(js_name = "maskAll")]
    pub fn mask_all(
        &self,
        aggregate_pk_x: &str,
        aggregate_pk_y: &str,
    ) -> Result<WasmMaskAllResult, JsValue> {
        let pk = parse_public_key(aggregate_pk_x, aggregate_pk_y)?;

        let mut masked_cards = Vec::new();
        let mut proofs = Vec::new();

        for card in &self.cards {
            let (masked, proof) = MentalPokerProtocol::mask(card, &pk, None)
                .map_err(|e| JsValue::from_str(&format!("Mask failed: {e}")))?;

            masked_cards.push(
                WasmMaskedCard::from_native(&masked)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?,
            );
            proofs.push(proof.into());
        }

        Ok(WasmMaskAllResult {
            masked_cards,
            proofs,
        })
    }
}

/// Result of masking all cards in a deck.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmMaskAllResult {
    pub masked_cards: Vec<WasmMaskedCard>,
    pub proofs: Vec<WasmDLEqualityProof>,
}

/// Create a standard 52-card deck.
#[wasm_bindgen(js_name = "createStandardDeck")]
pub fn create_standard_deck() -> WasmDeck {
    let cards: Vec<Card> = (1..=52).map(Card::from_index).collect();
    WasmDeck { cards }
}

/// Create a deck with a custom number of cards.
#[wasm_bindgen(js_name = "createDeck")]
pub fn create_deck(num_cards: u64) -> WasmDeck {
    let cards: Vec<Card> = (1..=num_cards).map(Card::from_index).collect();
    WasmDeck { cards }
}

/// Mask a single card.
#[wasm_bindgen(js_name = "maskCard")]
pub fn mask_card(
    card_index: u64,
    aggregate_pk_x: &str,
    aggregate_pk_y: &str,
) -> Result<WasmMaskResult, JsValue> {
    let pk = parse_public_key(aggregate_pk_x, aggregate_pk_y)?;
    let card = Card::from_index(card_index);

    let (masked, proof) = MentalPokerProtocol::mask(&card, &pk, None)
        .map_err(|e| JsValue::from_str(&format!("Mask failed: {e}")))?;

    Ok(WasmMaskResult {
        masked_card: WasmMaskedCard::from_native(&masked)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        proof: proof.into(),
    })
}

/// Remask a card (re-encrypt without changing the underlying card).
#[wasm_bindgen(js_name = "remaskCard")]
pub fn remask_card(
    masked: &WasmMaskedCard,
    aggregate_pk_x: &str,
    aggregate_pk_y: &str,
) -> Result<WasmMaskResult, JsValue> {
    let pk = parse_public_key(aggregate_pk_x, aggregate_pk_y)?;
    let native_masked = masked
        .to_native()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let (remasked, proof) = MentalPokerProtocol::remask(&native_masked, &pk, None)
        .map_err(|e| JsValue::from_str(&format!("Remask failed: {e}")))?;

    Ok(WasmMaskResult {
        masked_card: WasmMaskedCard::from_native(&remasked)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        proof: proof.into(),
    })
}

/// Unmask a card using reveal tokens from all players.
#[wasm_bindgen(js_name = "unmaskCard")]
pub fn unmask_card(masked: &WasmMaskedCard, reveal_tokens_json: &str) -> Result<WasmCard, JsValue> {
    use mental_poker::types::RevealToken;

    #[derive(Deserialize)]
    struct TokenInput {
        token_x: String,
        token_y: String,
        proof: crate::types::WasmDLEqualityProof,
        public_key: WasmPublicKey,
    }

    let tokens: Vec<TokenInput> = serde_json::from_str(reveal_tokens_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid tokens JSON: {e}")))?;

    let native_masked = masked
        .to_native()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut reveal_data: Vec<(RevealToken, mental_poker::types::DLEqualityProof, PublicKey)> =
        Vec::new();

    for t in tokens {
        let token_x = Felt::from_hex(&t.token_x)
            .map_err(|e| JsValue::from_str(&format!("Invalid token x: {e}")))?;
        let token_y = Felt::from_hex(&t.token_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid token y: {e}")))?;
        let token_point = ProjectivePoint::from_affine(token_x, token_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid token point: {e:?}")))?;

        let pk_x = Felt::from_hex(&t.public_key.x)
            .map_err(|e| JsValue::from_str(&format!("Invalid pk x: {e}")))?;
        let pk_y = Felt::from_hex(&t.public_key.y)
            .map_err(|e| JsValue::from_str(&format!("Invalid pk y: {e}")))?;
        let pk_point = ProjectivePoint::from_affine(pk_x, pk_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid pk point: {e:?}")))?;

        reveal_data.push((
            RevealToken::new(token_point),
            t.proof.into(),
            PublicKey::new(pk_point),
        ));
    }

    let card = MentalPokerProtocol::unmask(&native_masked, &reveal_data)
        .map_err(|e| JsValue::from_str(&format!("Unmask failed: {e}")))?;

    // Find the card index by checking against known card points
    // For a standard deck, cards are g^1, g^2, ..., g^52
    let card_affine = card
        .point
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid card point"))?;

    // We need to determine the card index
    // For now, we return the card with index 0 (unknown) and the point
    // A proper implementation would use a lookup table or baby-step giant-step
    Ok(WasmCard {
        index: 0, // Index needs to be determined by the caller
        point: WasmPoint {
            x: format!("{:#x}", card_affine.x()),
            y: format!("{:#x}", card_affine.y()),
        },
    })
}

/// Resolve a decrypted card point back to its original card index.
///
/// After unmasking a card, you get a point that corresponds to `g^index`.
/// This function finds which index (1 to deck_size) produced that point
/// by comparing against pre-computed card points.
///
/// # Arguments
/// * `card_point_x` - The X coordinate of the decrypted card point (hex string)
/// * `card_point_y` - The Y coordinate of the decrypted card point (hex string)
/// * `deck_size` - The maximum card index to search (e.g., 52 for a standard deck)
///
/// # Returns
/// The card index (1-based) if found, or an error if the point doesn't match any card.
///
/// # Example
/// ```typescript
/// const decryptedCard = unmaskCard(maskedCard, revealTokens);
/// const cardIndex = resolveCardIndex(
///     decryptedCard.point.x,
///     decryptedCard.point.y,
///     52
/// );
/// console.log(`Card index: ${cardIndex}`); // e.g., "Card index: 42"
/// ```
#[wasm_bindgen(js_name = "resolveCardIndex")]
pub fn resolve_card_index(
    card_point_x: &str,
    card_point_y: &str,
    deck_size: u32,
) -> Result<u32, JsValue> {
    use krusty_kms_crypto::StarkCurve;

    // Parse the input point - we already have affine coordinates (x, y)
    let target_x = Felt::from_hex(card_point_x)
        .map_err(|e| JsValue::from_str(&format!("Invalid card point x: {e}")))?;
    let target_y = Felt::from_hex(card_point_y)
        .map_err(|e| JsValue::from_str(&format!("Invalid card point y: {e}")))?;

    // Validate that the point is on the curve
    let _ = ProjectivePoint::from_affine(target_x, target_y)
        .map_err(|e| JsValue::from_str(&format!("Invalid card point: {e:?}")))?;

    // Check against all possible card indices (1-based)
    // Compare affine coordinates directly for reliable equality check
    for i in 1..=deck_size {
        let card = Card::from_index(i as u64);
        let card_affine = StarkCurve::projective_to_affine(&card.point)
            .map_err(|e| JsValue::from_str(&format!("Invalid card point at index {}: {}", i, e)))?;

        if card_affine.x() == target_x && card_affine.y() == target_y {
            return Ok(i);
        }
    }

    Err(JsValue::from_str(&format!(
        "Card not found in deck (searched indices 1 to {})",
        deck_size
    )))
}

/// Resolve a decrypted card point from bytes back to its original card index.
///
/// This is a convenience function that takes the card point as raw bytes (64 bytes)
/// instead of hex strings.
///
/// # Arguments
/// * `card_point_bytes` - The card point as 64 bytes (32 bytes x, 32 bytes y, big-endian)
/// * `deck_size` - The maximum card index to search (e.g., 52 for a standard deck)
///
/// # Returns
/// The card index (1-based) if found, or an error if the point doesn't match any card.
#[wasm_bindgen(js_name = "resolveCardIndexFromBytes")]
pub fn resolve_card_index_from_bytes(
    card_point_bytes: &[u8],
    deck_size: u32,
) -> Result<u32, JsValue> {
    use krusty_kms_crypto::StarkCurve;

    if card_point_bytes.len() != 64 {
        return Err(JsValue::from_str(&format!(
            "Invalid byte length: expected 64 bytes, got {}",
            card_point_bytes.len()
        )));
    }

    // Parse the point from bytes
    let x_bytes: [u8; 32] = card_point_bytes[0..32]
        .try_into()
        .map_err(|_| JsValue::from_str("Failed to parse x coordinate"))?;
    let y_bytes: [u8; 32] = card_point_bytes[32..64]
        .try_into()
        .map_err(|_| JsValue::from_str("Failed to parse y coordinate"))?;

    let target_x = Felt::from_bytes_be(&x_bytes);
    let target_y = Felt::from_bytes_be(&y_bytes);

    // Validate that the point is on the curve
    let _ = ProjectivePoint::from_affine(target_x, target_y)
        .map_err(|e| JsValue::from_str(&format!("Invalid card point: {e:?}")))?;

    // Check against all possible card indices (1-based)
    // Compare affine coordinates directly for reliable equality check
    for i in 1..=deck_size {
        let card = Card::from_index(i as u64);
        let card_affine = StarkCurve::projective_to_affine(&card.point)
            .map_err(|e| JsValue::from_str(&format!("Invalid card point at index {}: {}", i, e)))?;

        if card_affine.x() == target_x && card_affine.y() == target_y {
            return Ok(i);
        }
    }

    Err(JsValue::from_str(&format!(
        "Card not found in deck (searched indices 1 to {})",
        deck_size
    )))
}

/// Verify a shuffle proof.
#[wasm_bindgen(js_name = "verifyShuffleProof")]
pub fn verify_shuffle_proof(
    original_cards: Vec<WasmMaskedCard>,
    shuffled_cards: Vec<WasmMaskedCard>,
    aggregate_pk_x: &str,
    aggregate_pk_y: &str,
    proof_json: &str,
) -> Result<bool, JsValue> {
    let pk = parse_public_key(aggregate_pk_x, aggregate_pk_y)?;

    let original: Vec<MaskedCard> = original_cards
        .iter()
        .map(|c| c.to_native().map_err(|e| JsValue::from_str(&e.to_string())))
        .collect::<Result<_, _>>()?;

    let shuffled: Vec<MaskedCard> = shuffled_cards
        .iter()
        .map(|c| c.to_native().map_err(|e| JsValue::from_str(&e.to_string())))
        .collect::<Result<_, _>>()?;

    let proof: mental_poker::shuffle::ShuffleProof = serde_json::from_str(proof_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof JSON: {e}")))?;

    MentalPokerProtocol::verify_shuffle(&original, &shuffled, &pk, &proof)
        .map_err(|e| JsValue::from_str(&format!("Verification failed: {e}")))
}

// Helper to parse public key coordinates
fn parse_public_key(x: &str, y: &str) -> Result<PublicKey, JsValue> {
    let pk_x = Felt::from_hex(x).map_err(|e| JsValue::from_str(&format!("Invalid pk x: {e}")))?;
    let pk_y = Felt::from_hex(y).map_err(|e| JsValue::from_str(&format!("Invalid pk y: {e}")))?;

    let point = ProjectivePoint::from_affine(pk_x, pk_y)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {e:?}")))?;

    Ok(PublicKey::new(point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_create_standard_deck() {
        let deck = create_standard_deck();
        assert_eq!(deck.len(), 52);
    }

    #[wasm_bindgen_test]
    fn test_create_deck() {
        let deck = create_deck(10);
        assert_eq!(deck.len(), 10);
    }

    #[wasm_bindgen_test]
    fn test_get_card() {
        let deck = create_deck(5);
        let card = deck.get_card(0).unwrap();
        assert_eq!(card.index, 1);
        assert!(card.point.x.starts_with("0x"));
    }

    #[wasm_bindgen_test]
    fn test_masked_card_bytes_roundtrip() {
        // Create a masked card from valid points
        let deck = create_deck(1);
        let (pk, _) = mental_poker::MentalPokerProtocol::player_keygen();
        let pk_affine = pk.point.to_affine().unwrap();

        let result = deck
            .mask_all(
                &format!("{:#x}", pk_affine.x()),
                &format!("{:#x}", pk_affine.y()),
            )
            .unwrap();

        let masked = &result.masked_cards[0];
        let bytes = masked.to_bytes().unwrap();
        assert_eq!(bytes.len(), 128);

        let recovered = WasmMaskedCard::from_bytes(&bytes).unwrap();
        assert_eq!(masked.c0_x, recovered.c0_x);
        assert_eq!(masked.c0_y, recovered.c0_y);
    }

    // =========================================================================
    // TDD: Tests for malformed input handling (P0 critical WASM panic fixes)
    // These tests run only in wasm32 target since JsValue is wasm-only
    // =========================================================================

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_masked_card_from_bytes_empty_input_returns_error() {
        // Empty byte array should return an error, not panic
        let empty_bytes: &[u8] = &[];
        let result = WasmMaskedCard::from_bytes(empty_bytes);
        assert!(result.is_err(), "Empty input should return Err, not panic");
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_masked_card_from_bytes_short_input_returns_error() {
        // Short byte array (less than 128 bytes) should return an error, not panic
        let short_bytes: Vec<u8> = vec![0u8; 64]; // Only 64 bytes, needs 128
        let result = WasmMaskedCard::from_bytes(&short_bytes);
        assert!(result.is_err(), "Short input should return Err, not panic");
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_masked_card_from_bytes_127_bytes_returns_error() {
        // Off-by-one: 127 bytes should return error
        let almost_bytes: Vec<u8> = vec![0u8; 127];
        let result = WasmMaskedCard::from_bytes(&almost_bytes);
        assert!(result.is_err(), "127 bytes should return Err, not panic");
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_masked_card_from_bytes_oversized_input_returns_error() {
        // Too many bytes should return error (not silently truncate)
        let oversized_bytes: Vec<u8> = vec![0u8; 256];
        let result = WasmMaskedCard::from_bytes(&oversized_bytes);
        assert!(result.is_err(), "Oversized input should return Err");
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_masked_card_from_bytes_valid_128_bytes_succeeds() {
        // Valid 128 bytes should succeed
        let valid_bytes: Vec<u8> = vec![0u8; 128];
        let result = WasmMaskedCard::from_bytes(&valid_bytes);
        assert!(result.is_ok(), "Valid 128 bytes should succeed");
    }

    // =========================================================================
    // Tests for card index resolution
    // =========================================================================

    #[wasm_bindgen_test]
    fn test_resolve_card_index_valid_cards() {
        // Test resolving card indices 1 through 52
        let deck = create_deck(52);

        for i in 0..52 {
            let card = deck.get_card(i).unwrap();
            let resolved = resolve_card_index(&card.point.x, &card.point.y, 52).unwrap();
            assert_eq!(
                resolved,
                (i + 1) as u32,
                "Card at index {} should resolve to {}",
                i,
                i + 1
            );
        }
    }

    #[wasm_bindgen_test]
    fn test_resolve_card_index_first_card() {
        // Test that card index 1 resolves correctly
        let deck = create_deck(52);
        let card = deck.get_card(0).unwrap();

        let resolved = resolve_card_index(&card.point.x, &card.point.y, 52).unwrap();
        assert_eq!(resolved, 1);
    }

    #[wasm_bindgen_test]
    fn test_resolve_card_index_last_card() {
        // Test that card index 52 resolves correctly
        let deck = create_deck(52);
        let card = deck.get_card(51).unwrap();

        let resolved = resolve_card_index(&card.point.x, &card.point.y, 52).unwrap();
        assert_eq!(resolved, 52);
    }

    #[wasm_bindgen_test]
    fn test_resolve_card_index_small_deck() {
        // Test with a small deck (10 cards)
        let deck = create_deck(10);

        for i in 0..10 {
            let card = deck.get_card(i).unwrap();
            let resolved = resolve_card_index(&card.point.x, &card.point.y, 10).unwrap();
            assert_eq!(resolved, (i + 1) as u32);
        }
    }

    #[wasm_bindgen_test]
    fn test_resolve_card_index_from_bytes_valid() {
        // Test the bytes-based resolution
        let deck = create_deck(52);
        let card = deck.get_card(0).unwrap();

        // Convert point to bytes
        let bytes = card.point.to_bytes().unwrap();
        let resolved = resolve_card_index_from_bytes(&bytes, 52).unwrap();
        assert_eq!(resolved, 1);
    }

    #[wasm_bindgen_test]
    fn test_resolve_card_index_from_bytes_all_cards() {
        // Test bytes-based resolution for multiple cards
        let deck = create_deck(10);

        for i in 0..10 {
            let card = deck.get_card(i).unwrap();
            let bytes = card.point.to_bytes().unwrap();
            let resolved = resolve_card_index_from_bytes(&bytes, 10).unwrap();
            assert_eq!(
                resolved,
                (i + 1) as u32,
                "Card {} should resolve correctly from bytes",
                i
            );
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_resolve_card_index_not_found() {
        // Test that an invalid point returns an error
        // Use a point that's not in the deck (g^100 when deck is only 52)
        let deck = create_deck(100);
        let card = deck.get_card(99).unwrap(); // This is card index 100

        let result = resolve_card_index(&card.point.x, &card.point.y, 52);
        assert!(
            result.is_err(),
            "Card index 100 should not be found in 52-card deck"
        );
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_resolve_card_index_invalid_hex() {
        // Test with invalid hex string
        let result = resolve_card_index("not_valid_hex", "0x1234", 52);
        assert!(result.is_err(), "Invalid hex should return error");
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_resolve_card_index_from_bytes_wrong_length() {
        // Test with wrong byte length
        let short_bytes: Vec<u8> = vec![0u8; 32]; // Only 32 bytes, needs 64
        let result = resolve_card_index_from_bytes(&short_bytes, 52);
        assert!(result.is_err(), "Wrong byte length should return error");
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_resolve_card_index_from_bytes_empty() {
        // Test with empty bytes
        let empty_bytes: &[u8] = &[];
        let result = resolve_card_index_from_bytes(empty_bytes, 52);
        assert!(result.is_err(), "Empty bytes should return error");
    }
}
