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

// RPC providers can control typed error messages, so a count-only operation
// limit is insufficient. Keep returned and retained detail allocations bounded.
const MAX_GATEWAY_ERROR_MESSAGE_BYTES: usize = 1_024;
const TRUNCATION_MARKER: &str = "… [truncated]";

impl GatewayError {
    pub fn new(
        code: GatewayErrorCode,
        retryable: bool,
        message: impl Into<Option<String>>,
    ) -> Self {
        let mut error = Self {
            code,
            retryable,
            message: message.into(),
        };
        error.bound_message();
        error
    }

    fn bound_message(&mut self) {
        let Some(message) = &mut self.message else {
            return;
        };
        let truncated = message.len() > MAX_GATEWAY_ERROR_MESSAGE_BYTES;
        let end = if truncated {
            let mut end = MAX_GATEWAY_ERROR_MESSAGE_BYTES - TRUNCATION_MARKER.len();
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            end
        } else {
            message.len()
        };

        // Truncating in place keeps the provider-controlled allocation alive.
        // A fresh bounded allocation also handles short strings with excess capacity.
        let capacity = end
            + if truncated {
                TRUNCATION_MARKER.len()
            } else {
                0
            };
        let mut bounded = String::with_capacity(capacity);
        bounded.push_str(&message[..end]);
        if truncated {
            bounded.push_str(TRUNCATION_MARKER);
        }
        *message = bounded;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_error_releases_oversized_message_allocations() {
        let mut large = String::with_capacity(64 * 1024);
        large.push_str(&"🔒".repeat(4_096));
        let error = GatewayError::new(GatewayErrorCode::RpcDegraded, true, Some(large));
        let message = error.message.unwrap();
        assert!(message.len() <= MAX_GATEWAY_ERROR_MESSAGE_BYTES);
        assert!(message.capacity() <= 2 * MAX_GATEWAY_ERROR_MESSAGE_BYTES);
        assert!(message.ends_with(TRUNCATION_MARKER));

        let mut short = String::with_capacity(64 * 1024);
        short.push_str("synthetic error");
        let error = GatewayError::new(GatewayErrorCode::RpcDegraded, true, Some(short));
        let message = error.message.unwrap();
        assert_eq!(message, "synthetic error");
        assert!(message.capacity() <= 2 * MAX_GATEWAY_ERROR_MESSAGE_BYTES);
    }
}
