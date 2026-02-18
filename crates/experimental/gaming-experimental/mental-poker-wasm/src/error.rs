//! Error types for WASM mental poker operations.

use thiserror::Error;
use wasm_bindgen::prelude::*;

/// Mental poker WASM error type.
#[derive(Error, Debug)]
pub enum WasmMentalPokerError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid card index: {0}")]
    InvalidCardIndex(u64),

    #[error("Deck operation failed: {0}")]
    DeckError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<WasmMentalPokerError> for JsValue {
    fn from(err: WasmMentalPokerError) -> Self {
        JsValue::from_str(&err.to_string())
    }
}

impl From<mental_poker::MentalPokerError> for WasmMentalPokerError {
    fn from(err: mental_poker::MentalPokerError) -> Self {
        WasmMentalPokerError::CryptoError(err.to_string())
    }
}

impl From<ghoul_common::GhoulError> for WasmMentalPokerError {
    fn from(err: ghoul_common::GhoulError) -> Self {
        WasmMentalPokerError::InternalError(err.to_string())
    }
}
