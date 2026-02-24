//! Validated Starknet address (Felt newtype).

use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use std::fmt;

use crate::{KmsError, Result};

/// A validated Starknet contract address.
///
/// Wraps a `Felt` and ensures it was parsed from a valid hex string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Address(Felt);

impl Address {
    /// Parse an address from a hex string (with or without `0x` prefix).
    pub fn from_hex(hex: &str) -> Result<Self> {
        let felt =
            Felt::from_hex(hex).map_err(|e| KmsError::DeserializationError(e.to_string()))?;
        Ok(Self(felt))
    }

    /// Return the inner Felt.
    pub fn as_felt(&self) -> Felt {
        self.0
    }

    /// Return the hex representation with `0x` prefix.
    pub fn to_hex(&self) -> String {
        format!("{:#066x}", self.0)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#066x}", self.0)
    }
}

impl From<Felt> for Address {
    fn from(felt: Felt) -> Self {
        Self(felt)
    }
}

impl From<Address> for Felt {
    fn from(addr: Address) -> Self {
        addr.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_hex() {
        let addr =
            Address::from_hex("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
                .unwrap();
        assert_ne!(addr.as_felt(), Felt::ZERO);
    }

    #[test]
    fn test_from_hex_invalid() {
        assert!(Address::from_hex("not_hex").is_err());
    }

    #[test]
    fn test_display_roundtrip() {
        let hex = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
        let addr = Address::from_hex(hex).unwrap();
        let displayed = addr.to_hex();
        let addr2 = Address::from_hex(&displayed).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_from_felt() {
        let felt = Felt::from(42u64);
        let addr = Address::from(felt);
        assert_eq!(addr.as_felt(), felt);
    }

    #[test]
    fn test_serde_roundtrip() {
        let addr = Address::from_hex("0x123").unwrap();
        let json = serde_json::to_string(&addr).unwrap();
        let parsed: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, parsed);
    }
}
