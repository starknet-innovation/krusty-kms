//! WASM error handling.
//!
//! Provides JavaScript-friendly error types that wrap internal Rust errors.
//! All errors are converted to `JsValue` for proper error propagation to JS.

use wasm_bindgen::prelude::*;

/// WASM-compatible error type.
///
/// Wraps internal errors for JavaScript interop. All error variants
/// include a human-readable message accessible from JS.
#[derive(Debug)]
pub enum WasmError {
    /// Invalid mnemonic phrase
    InvalidMnemonic(String),
    /// Invalid private key format or value
    InvalidPrivateKey(String),
    /// Invalid public key format or value
    InvalidPublicKey(String),
    /// Cryptographic operation failed
    CryptoError(String),
    /// Serialization/deserialization error
    SerializationError(String),
    /// Insufficient balance for operation
    InsufficientBalance { available: u128, required: u128 },
    /// Invalid amount specified
    InvalidAmount(String),
    /// Proof generation or verification failed
    ProofError(String),
    /// Internal SDK error
    InternalError(String),
}

impl WasmError {
    /// Convert error to a JavaScript Error object with proper message.
    fn to_js_error(&self) -> JsValue {
        let msg = match self {
            Self::InvalidMnemonic(s) => format!("Invalid mnemonic: {s}"),
            Self::InvalidPrivateKey(s) => format!("Invalid private key: {s}"),
            Self::InvalidPublicKey(s) => format!("Invalid public key: {s}"),
            Self::CryptoError(s) => format!("Crypto error: {s}"),
            Self::SerializationError(s) => format!("Serialization error: {s}"),
            Self::InsufficientBalance { available, required } => {
                format!("Insufficient balance: available={available}, required={required}")
            }
            Self::InvalidAmount(s) => format!("Invalid amount: {s}"),
            Self::ProofError(s) => format!("Proof error: {s}"),
            Self::InternalError(s) => format!("Internal error: {s}"),
        };

        js_sys::Error::new(&msg).into()
    }

    /// Error code for programmatic handling in JavaScript.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidMnemonic(_) => "INVALID_MNEMONIC",
            Self::InvalidPrivateKey(_) => "INVALID_PRIVATE_KEY",
            Self::InvalidPublicKey(_) => "INVALID_PUBLIC_KEY",
            Self::CryptoError(_) => "CRYPTO_ERROR",
            Self::SerializationError(_) => "SERIALIZATION_ERROR",
            Self::InsufficientBalance { .. } => "INSUFFICIENT_BALANCE",
            Self::InvalidAmount(_) => "INVALID_AMOUNT",
            Self::ProofError(_) => "PROOF_ERROR",
            Self::InternalError(_) => "INTERNAL_ERROR",
        }
    }
}

impl From<WasmError> for JsValue {
    fn from(err: WasmError) -> Self {
        err.to_js_error()
    }
}

impl From<ghoul_common::GhoulError> for WasmError {
    fn from(err: ghoul_common::GhoulError) -> Self {
        match err {
            ghoul_common::GhoulError::InvalidMnemonic(s) => Self::InvalidMnemonic(s),
            ghoul_common::GhoulError::InvalidPrivateKey(s) => Self::InvalidPrivateKey(s),
            ghoul_common::GhoulError::InvalidPublicKey(s) => Self::InvalidPublicKey(s),
            ghoul_common::GhoulError::CryptoError(s) => Self::CryptoError(s),
            ghoul_common::GhoulError::SerializationError(s) => Self::SerializationError(s),
            ghoul_common::GhoulError::DeserializationError(s) => Self::SerializationError(s),
            ghoul_common::GhoulError::InsufficientBalance { available, required } => {
                Self::InsufficientBalance { available, required }
            }
            ghoul_common::GhoulError::InvalidAmount(s) => Self::InvalidAmount(s),
            ghoul_common::GhoulError::InvalidProof(s) => Self::ProofError(s),
            ghoul_common::GhoulError::PointAtInfinity => {
                Self::CryptoError("Point at infinity".to_string())
            }
            ghoul_common::GhoulError::InvalidDerivationPath(s) => Self::InvalidPrivateKey(s),
            ghoul_common::GhoulError::HexError(e) => Self::SerializationError(e.to_string()),
            ghoul_common::GhoulError::JsonError(e) => Self::SerializationError(e.to_string()),
            ghoul_common::GhoulError::StarknetCryptoError(s) => Self::CryptoError(s),
            ghoul_common::GhoulError::RpcError(s) => Self::InternalError(s),
        }
    }
}

/// Result type for WASM operations.
pub type WasmResult<T> = Result<T, WasmError>;

/// Convert a ghoul_common::Result to WasmResult.
pub fn from_sdk_result<T>(result: ghoul_common::Result<T>) -> WasmResult<T> {
    result.map_err(WasmError::from)
}
