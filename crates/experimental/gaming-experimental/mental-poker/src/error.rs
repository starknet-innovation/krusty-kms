//! Error types for the mental poker protocol.

use thiserror::Error;

/// Errors that can occur during mental poker protocol execution.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum MentalPokerError {
    /// Failed to verify a zero-knowledge proof
    #[error("Proof verification failed: {0}")]
    ProofVerificationError(String),

    /// Invalid key ownership proof
    #[error("Invalid key ownership proof")]
    InvalidKeyOwnership,

    /// Invalid masking proof
    #[error("Invalid masking proof")]
    InvalidMaskingProof,

    /// Invalid remasking proof
    #[error("Invalid remasking proof")]
    InvalidRemaskingProof,

    /// Invalid reveal proof
    #[error("Invalid reveal proof")]
    InvalidRevealProof,

    /// Invalid shuffle proof
    #[error("Invalid shuffle proof")]
    InvalidShuffleProof,

    /// Invalid card - card not found in deck mapping
    #[error("Invalid card: not found in deck mapping")]
    InvalidCard,

    /// Card not found in player's hand
    #[error("Card not found in hand")]
    CardNotFound,

    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid point on curve
    #[error("Invalid curve point")]
    InvalidPoint,

    /// Cryptographic operation failed
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Insufficient reveal tokens
    #[error("Insufficient reveal tokens to unmask card")]
    InsufficientRevealTokens,

    /// Invalid card index (0 produces identity point)
    #[error("Invalid card index: {0}")]
    InvalidCardIndex(String),

    /// Invalid deck configuration
    #[error("Invalid deck configuration: {0}")]
    InvalidDeckConfig(String),
}

impl From<ghoul_common::GhoulError> for MentalPokerError {
    fn from(err: ghoul_common::GhoulError) -> Self {
        MentalPokerError::CryptoError(err.to_string())
    }
}

/// Result type alias for mental poker operations.
pub type Result<T> = std::result::Result<T, MentalPokerError>;
