//! Validation and gateway/runtime error types.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for domain-contract values.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid felt hex: {0}")]
    InvalidFeltHex(String),
    #[error("invalid hex bytes: {0}")]
    InvalidHexBytes(String),
    #[error("invalid {field}: value must not be empty")]
    EmptyField { field: &'static str },
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),
    #[error("invalid cache policy: {0}")]
    InvalidCachePolicy(&'static str),
    #[error("invalid wait policy: {0}")]
    InvalidWaitPolicy(&'static str),
    #[error("invalid sign request: {0}")]
    InvalidSignRequest(String),
    #[error("invalid secret_ref: {0}")]
    InvalidSecretRef(String),
}

/// Machine-readable gateway/runtime failure codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayErrorCode {
    Undeployed,
    NotFound,
    ProviderTransport,
    InsufficientBalance,
    InsufficientFee,
    NonceMismatch,
    InvalidRequest,
    InvalidClassHash,
    ConstructorCalldataMismatch,
    InvalidDerivationPath,
    InvalidCachePolicy,
    InvalidWaitPolicy,
    UnsupportedKeyDomain,
    UnsupportedAccountClass,
    ChainMismatch,
    UnsupportedProtocolVersion,
    UnsupportedSigningDomain,
    CacheUnavailable,
    CacheStale,
    RpcDegraded,
    Timeout,
    SecretUnavailable,
    Internal,
}

/// Structured gateway/runtime error payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayError {
    pub code: GatewayErrorCode,
    pub retryable: bool,
    pub message: Option<String>,
}

impl GatewayError {
    pub fn new(
        code: GatewayErrorCode,
        retryable: bool,
        message: impl Into<Option<String>>,
    ) -> Self {
        Self {
            code,
            retryable,
            message: message.into(),
        }
    }
}
