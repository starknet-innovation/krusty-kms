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
pub use token::Token;
pub use types::*;
pub use validator::Validator;
