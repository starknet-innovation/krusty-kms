//! Mental Poker WASM SDK
//!
//! WebAssembly bindings for the mental poker protocol, enabling secure card games
//! in the browser without a trusted dealer.
//!
//! # Usage from JavaScript/TypeScript
//!
//! ```typescript
//! import init, {
//!   WasmPlayer,
//!   WasmDeck,
//!   generateKeypair,
//!   createStandardDeck,
//! } from 'mental-poker-wasm';
//!
//! // Initialize WASM module
//! await init();
//!
//! // Generate player keys
//! const player1 = generateKeypair();
//! const player2 = generateKeypair();
//!
//! // Create aggregate key from all players
//! const aggregateKey = aggregatePublicKeys([
//!   { proof: player1.keyOwnershipProof, publicKey: player1.publicKey, context: "player1" },
//!   { proof: player2.keyOwnershipProof, publicKey: player2.publicKey, context: "player2" },
//! ]);
//!
//! // Create and shuffle deck
//! const deck = createStandardDeck(aggregateKey);
//! const shuffled = deck.shuffleWithProof(aggregateKey);
//! ```
//!
//! # Features
//!
//! - **Key Generation**: Schnorr-style keypairs with proofs of ownership
//! - **Deck Management**: Create, shuffle, and deal cards
//! - **Card Operations**: Mask, remask, reveal with zero-knowledge proofs
//! - **Batch Operations**: Efficient handling of multiple cards
//! - **Compact Serialization**: Efficient binary formats for network transfer

#![allow(clippy::new_without_default)]

pub mod blackjack;
pub mod crossy;
pub mod deck;
pub mod error;
pub mod player;
pub mod types;

use wasm_bindgen::prelude::*;

// Re-export main types
pub use blackjack::{
    blackjack_best_value, blackjack_card_suit, blackjack_card_value, blackjack_outcome_display,
    blackjack_rank_symbol, blackjack_suit_symbol, calculate_blackjack_hand_value,
    calculate_blackjack_payout, create_blackjack_deck, determine_blackjack_winner,
    format_blackjack_card, get_blackjack_card_indices, is_blackjack_ace, is_blackjack_bust,
    is_blackjack_face_card, is_blackjack_player_win, is_blackjack_push, is_blackjack_ten_value,
    is_blackjack_wasm, should_dealer_hit_soft17_wasm, should_dealer_hit_wasm,
    WasmBlackjackDeckConfig, WasmBlackjackOutcome, WasmHandValue,
};
pub use crossy::{
    calculate_crossy_multiplier, create_crossy_deck, get_crossy_card_index_for_lane,
    get_crossy_card_indices, get_crossy_difficulty_name, get_crossy_total_rows,
    is_crossy_hit_card, is_crossy_survive_card, resolve_crossy_card_type_wasm,
    WasmCrossyDeckConfig,
};
pub use deck::{
    create_standard_deck, resolve_card_index, resolve_card_index_from_bytes, WasmDeck,
    WasmMaskedCard, WasmMaskedDeck, WasmShuffleProofResult,
};
pub use error::WasmMentalPokerError;
pub use player::{
    aggregate_public_keys, generate_keypair, verify_key_ownership, WasmAggregateKeyInput,
    WasmPlayer,
};
pub use types::{
    WasmCard, WasmCompactMaskedCard, WasmCompactProof, WasmDLEqualityProof, WasmKeyOwnershipProof,
    WasmPoint, WasmPublicKey, WasmRevealToken,
};

/// Initialize the WASM module.
///
/// Sets up panic hook for better error messages in console.
/// Call this before using any other functions.
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Get the SDK version.
#[wasm_bindgen(js_name = "getVersion")]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get build information.
#[wasm_bindgen(js_name = "getBuildInfo")]
pub fn get_build_info() -> JsValue {
    use serde_json::json;

    let info = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": env!("CARGO_PKG_NAME"),
        "target": "wasm32-unknown-unknown",
        "features": {
            "console_error_panic_hook": cfg!(feature = "console_error_panic_hook"),
        }
    });

    serde_wasm_bindgen::to_value(&info).unwrap_or(JsValue::NULL)
}

// ============================================================================
// Cryptographic Utilities
// ============================================================================

/// Generate a random field element.
#[wasm_bindgen(js_name = "randomFelt")]
pub fn random_felt() -> String {
    use rand::Rng;
    use starknet_types_core::felt::Felt;

    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    let felt = Felt::from_bytes_be(&bytes);
    format!("{:#x}", felt)
}

/// Get the Stark curve generator point.
#[wasm_bindgen(js_name = "getGenerator")]
pub fn get_generator() -> types::WasmPoint {
    use krusty_kms_crypto::StarkCurve;

    let g = StarkCurve::generator();
    let affine = g.to_affine().expect("Generator is never at infinity");

    types::WasmPoint {
        x: format!("{:#x}", affine.x()),
        y: format!("{:#x}", affine.y()),
    }
}

/// Add two points on the Stark curve.
#[wasm_bindgen(js_name = "pointAdd")]
pub fn point_add(
    p1_x: &str,
    p1_y: &str,
    p2_x: &str,
    p2_y: &str,
) -> Result<types::WasmPoint, JsValue> {
    use starknet_types_core::curve::ProjectivePoint;
    use starknet_types_core::felt::Felt;

    let p1x =
        Felt::from_hex(p1_x).map_err(|e| JsValue::from_str(&format!("Invalid P1 X: {e}")))?;
    let p1y =
        Felt::from_hex(p1_y).map_err(|e| JsValue::from_str(&format!("Invalid P1 Y: {e}")))?;
    let p2x =
        Felt::from_hex(p2_x).map_err(|e| JsValue::from_str(&format!("Invalid P2 X: {e}")))?;
    let p2y =
        Felt::from_hex(p2_y).map_err(|e| JsValue::from_str(&format!("Invalid P2 Y: {e}")))?;

    let p1 = ProjectivePoint::from_affine(p1x, p1y)
        .map_err(|e| JsValue::from_str(&format!("Invalid P1: {e:?}")))?;
    let p2 = ProjectivePoint::from_affine(p2x, p2y)
        .map_err(|e| JsValue::from_str(&format!("Invalid P2: {e:?}")))?;

    let result = &p1 + &p2;
    let affine = result
        .to_affine()
        .map_err(|_| JsValue::from_str("Result is point at infinity"))?;

    Ok(types::WasmPoint {
        x: format!("{:#x}", affine.x()),
        y: format!("{:#x}", affine.y()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_generator() {
        let g = get_generator();
        assert!(g.x.starts_with("0x"));
        assert!(g.y.starts_with("0x"));
    }

    #[wasm_bindgen_test]
    fn test_random_felt() {
        let r1 = random_felt();
        let r2 = random_felt();
        assert!(r1.starts_with("0x"));
        assert!(r2.starts_with("0x"));
        assert_ne!(r1, r2);
    }

    #[wasm_bindgen_test]
    fn test_point_add() {
        let g = get_generator();
        let result = point_add(&g.x, &g.y, &g.x, &g.y);
        assert!(result.is_ok());
    }
}
