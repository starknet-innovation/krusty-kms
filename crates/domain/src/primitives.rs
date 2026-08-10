//! Canonical value primitives: hex encodings, secret references, identifiers.

use crate::error::DomainError;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use std::fmt;

/// Canonical felt-like hex string.
///
/// Values are normalized to `0x` followed by exactly 64 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FeltHex(String);

impl FeltHex {
    /// Parse and canonicalize a felt hex string.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let felt = Felt::from_hex(value).map_err(|e| DomainError::InvalidFeltHex(e.to_string()))?;
        // Upstream `Felt::from_hex` has an off-by-one at the field prime: it
        // accepts exactly p and aliases it to 0. Verify the parsed value
        // round-trips to the input so any aliased (>= p) input is rejected.
        let canonical = format!("{felt:064x}");
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        let is_canonical =
            trimmed.len() <= 64 && format!("{:0>64}", trimmed.to_ascii_lowercase()) == canonical;
        if !is_canonical {
            return Err(DomainError::InvalidFeltHex(format!(
                "value is not a canonical field element: {value}"
            )));
        }
        Ok(Self(format!("0x{canonical}")))
    }

    /// Convert a felt value to its canonical hex representation.
    pub fn from_felt(value: Felt) -> Self {
        Self(format!("0x{:064x}", value))
    }

    /// Return the canonical string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert back to a felt value.
    pub fn to_felt(&self) -> Felt {
        Felt::from_hex(&self.0).expect("FeltHex stores only validated values")
    }
}

impl fmt::Display for FeltHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for FeltHex {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<FeltHex> for String {
    fn from(value: FeltHex) -> Self {
        value.0
    }
}

/// Canonical lowercase hex bytes without a `0x` prefix.
///
/// Values are normalized to lowercase and must contain an even number of hex
/// digits so they round-trip exactly as bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HexBytes(String);

impl HexBytes {
    /// Parse and canonicalize a hex byte string.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let trimmed = value.trim();
        let normalized = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);

        if normalized.is_empty() {
            return Err(DomainError::InvalidHexBytes(
                "value must not be empty".to_string(),
            ));
        }

        if !normalized.len().is_multiple_of(2) {
            return Err(DomainError::InvalidHexBytes(
                "hex byte strings must have an even number of digits".to_string(),
            ));
        }

        if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidHexBytes(
                "value contains non-hex characters".to_string(),
            ));
        }

        Ok(Self(normalized.to_ascii_lowercase()))
    }

    /// Convert bytes to canonical lowercase hex.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(bytes))
    }

    /// Return the canonical lowercase hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decode into a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        hex::decode(&self.0).expect("HexBytes stores only validated values")
    }

    /// Decode into an exact-size array.
    pub fn to_array<const N: usize>(&self) -> Result<[u8; N], DomainError> {
        let bytes = self.to_vec();
        let actual_len = bytes.len();
        bytes.try_into().map_err(|_| {
            DomainError::InvalidHexBytes(format!("expected exactly {N} bytes, got {}", actual_len))
        })
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for HexBytes {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<HexBytes> for String {
    fn from(value: HexBytes) -> Self {
        value.0
    }
}

/// Stable identifier for a secret kept behind the trusted boundary.
///
/// Labels are global and unauthenticated: any caller that can reach the
/// gateway/oracle can reference any label. There is no tenant namespacing —
/// the transport boundary is the only isolation. See
/// `docs/oracle-stdio-v1.md` § Trust Model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretRef(String);

impl SecretRef {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DomainError::EmptyField {
                field: "secret_ref",
            });
        }
        if looks_like_raw_secret_material(&value) {
            return Err(DomainError::InvalidSecretRef(
                "must be an opaque identifier, not raw key material".to_string(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reject SecretRef values that look like hex private keys or BIP-39 mnemonics.
fn looks_like_raw_secret_material(value: &str) -> bool {
    let trimmed = value.trim();
    let (has_0x, hex_body) = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(body) => (true, body),
        None => (false, trimmed),
    };

    if !hex_body.is_empty() && hex_body.chars().all(|c| c.is_ascii_hexdigit()) {
        // Leading zeroes do not change the underlying scalar, so a padded
        // encoding (`0x0` + 64 digits) must be treated like its unpadded form.
        // Check both the literal width and the significant width.
        let significant_len = hex_body.trim_start_matches('0').len();
        let widths = [hex_body.len(), significant_len];

        // `0x`-prefixed values in the felt/scalar width range are key material
        // (including unpadded Stark scalars from `expose_secret_hex`).
        if has_0x && widths.iter().any(|w| *w <= 64) {
            return true;
        }
        // Bare hex long enough to be a near-full 32-byte key; keep short opaque
        // hex IDs (e.g. "abc123") allowed.
        if !has_0x && widths.iter().any(|w| (48..=64).contains(w)) {
            return true;
        }
    }

    let word_count = trimmed.split_whitespace().count();
    // 12+ space-separated tokens strongly suggests a mnemonic phrase.
    word_count >= 12
}

impl TryFrom<String> for SecretRef {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SecretRef> for String {
    fn from(value: SecretRef) -> Self {
        value.0
    }
}

/// Stable identifier for an operation tracked by a gateway.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(String);

impl OperationId {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DomainError::EmptyField {
                field: "operation_id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OperationId {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0
    }
}

/// Version tag for gateway/oracle protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const V1_0: Self = Self { major: 1, minor: 0 };
}
