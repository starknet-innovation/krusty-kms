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
/// authority is dropped, as is the userinfo. The scheme and `host[:port]`
/// are validated as URL components; anything that does not parse as a
/// plain scheme, host name / IP literal and numeric port yields
/// [`REDACTED_URL_PLACEHOLDER`] rather than the original text, so an
/// unparseable or credential-shaped value can never leak through.
#[must_use]
pub fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return REDACTED_URL_PLACEHOLDER.to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_userinfo, host)| host);
    if is_url_scheme(scheme) && is_host_port(host_port) {
        format!("{scheme}://{host_port}")
    } else {
        REDACTED_URL_PLACEHOLDER.to_string()
    }
}

/// RFC 3986 scheme: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn is_url_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// `host[:port]` where host is a DNS name / IPv4 literal or a bracketed IPv6
/// literal that parses as an address, and the optional port is numeric. Rejects anything else, such as
/// `user:secret` left over from a malformed userinfo.
fn is_host_port(host_port: &str) -> bool {
    let (host_ok, port) = match host_port.strip_prefix('[') {
        Some(rest) => {
            let Some((ipv6, after)) = rest.split_once(']') else {
                return false;
            };
            // Parse, do not pattern-match: `[deadbeef]` is hex-shaped but not an
            // address and must not be echoed.
            let ipv6_ok = ipv6.parse::<std::net::Ipv6Addr>().is_ok();
            let port = match after.strip_prefix(':') {
                Some(port) => Some(port),
                None if after.is_empty() => None,
                None => return false,
            };
            (ipv6_ok, port)
        }
        None => match host_port.rsplit_once(':') {
            Some((host, port)) => (is_host_name(host), Some(port)),
            None => (is_host_name(host_port), None),
        },
    };
    host_ok && port.is_none_or(is_port)
}

/// Decimal port that fits a `u16`: no sign, no empty string, no value above 65535.
fn is_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok()
}

fn is_host_name(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
}

#[cfg(test)]
mod tests;
