//! Common types and utilities for TONGO protocol implementation.
//!
//! This crate provides shared functionality used across all TONGO crates:
//! - Type conversions between different numeric representations
//! - Field element operations
//! - Serialization/deserialization helpers
//! - Error types

pub mod address;
pub mod amount;
pub mod chain;
pub mod error;
pub mod network;
pub mod secret_felt;
pub mod serialization;
pub mod token;
pub mod types;
pub mod utils;
pub mod validator;

pub use address::Address;
pub use amount::Amount;
pub use chain::ChainId;
pub use error::{KmsError, Result};
pub use network::NetworkPreset;
pub use secret_felt::SecretFelt;
pub use serialization::{
    deserialize_projective_point, serialize_ae_balance, serialize_audit_proof, serialize_bit_proof,
    serialize_cairo_none, serialize_cairo_some, serialize_cipher_balance, serialize_elgamal_proof,
    serialize_poe2_proof, serialize_poe_proof, serialize_projective_point,
    serialize_proof_of_transfer, serialize_range, u128_to_u256, u256_to_u128,
};
pub use token::Token;
pub use types::{
    AccountState, AuditProof, ElGamalCiphertext, ElGamalProof, Poe2Proof, PoeProof, ProofOfBit,
    ProofOfTransfer, Range, SerializablePoint, TransactionType,
};
pub use validator::Validator;
