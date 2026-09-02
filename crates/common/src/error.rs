//! Error types for Tongo protocol operations.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, KmsError>;

#[derive(Error, Debug)]
pub enum KmsError {
    #[error("Invalid public key format: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    // Deliberately carries no amounts: the available balance is confidential
    // plaintext and error strings routinely cross into JS/FFI/logs.
    #[error("Insufficient balance for requested amount (values withheld)")]
    InsufficientBalance,

    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Starknet crypto error: {0}")]
    StarknetCryptoError(String),

    #[error("Point at infinity")]
    PointAtInfinity,

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Account not deployed at {0}")]
    AccountNotDeployed(String),

    #[error("Account already deployed at {0}")]
    AlreadyDeployed(String),

    #[error("Insufficient fee balance for deployment: {0}")]
    InsufficientFeeBalance(String),

    #[error("Invalid class hash: {0}")]
    InvalidClassHash(String),

    #[error("Contract not found: {0}")]
    ContractNotFound(String),

    #[error("Transaction error: {0}")]
    TransactionError(String),

    #[error("Transaction reverted: {0}")]
    TransactionReverted(String),

    #[error("Fee estimation failed: {0}")]
    FeeEstimationFailed(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Staking error: {0}")]
    StakingError(String),

    #[error("Multisig error: {0}")]
    MultisigError(String),

    #[error("Controller error: {0}")]
    ControllerError(String),
}

/// Placeholder returned by [`redact_url`] when the input has no `scheme://host`.
pub const REDACTED_URL_PLACEHOLDER: &str = "<redacted-url>";

/// Reduce a URL to `scheme://host[:port]` for error messages and logs.
///
/// RPC endpoint URLs routinely carry the provider API key in the path or
/// query, and `userinfo` may carry credentials. Everything after the
/// authority is dropped, as is the userinfo. Inputs without a recognisable
/// `scheme://host` prefix yield [`REDACTED_URL_PLACEHOLDER`] rather than the
/// original text, so an unparseable value can never leak through.
#[must_use]
pub fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return REDACTED_URL_PLACEHOLDER.to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_userinfo, host)| host);
    if scheme.is_empty() || host_port.is_empty() {
        return REDACTED_URL_PLACEHOLDER.to_string();
    }
    format!("{scheme}://{host_port}")
}

#[cfg(test)]
mod tests;
