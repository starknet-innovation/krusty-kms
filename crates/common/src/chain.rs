//! Chain ID enum for Starknet networks.

use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

use crate::{KmsError, Result};

/// Starknet chain identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    Mainnet,
    Sepolia,
}

impl ChainId {
    /// The chain ID as a Felt (Cairo short-string encoded).
    pub fn as_felt(&self) -> Felt {
        match self {
            // "SN_MAIN" as Cairo short string
            ChainId::Mainnet => Felt::from_bytes_be_slice(b"SN_MAIN"),
            // "SN_SEPOLIA" as Cairo short string
            ChainId::Sepolia => Felt::from_bytes_be_slice(b"SN_SEPOLIA"),
        }
    }

    /// Parse from a Felt chain ID value.
    pub fn from_felt(felt: &Felt) -> Result<Self> {
        let mainnet = Felt::from_bytes_be_slice(b"SN_MAIN");
        let sepolia = Felt::from_bytes_be_slice(b"SN_SEPOLIA");
        if *felt == mainnet {
            Ok(ChainId::Mainnet)
        } else if *felt == sepolia {
            Ok(ChainId::Sepolia)
        } else {
            Err(KmsError::DeserializationError(format!(
                "Unknown chain ID: {:#x}",
                felt
            )))
        }
    }

    /// Human-readable chain name.
    pub fn name(&self) -> &'static str {
        match self {
            ChainId::Mainnet => "SN_MAIN",
            ChainId::Sepolia => "SN_SEPOLIA",
        }
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_felt_roundtrip() {
        let mainnet_felt = ChainId::Mainnet.as_felt();
        assert_eq!(ChainId::from_felt(&mainnet_felt).unwrap(), ChainId::Mainnet);

        let sepolia_felt = ChainId::Sepolia.as_felt();
        assert_eq!(
            ChainId::from_felt(&sepolia_felt).unwrap(),
            ChainId::Sepolia
        );
    }

    #[test]
    fn test_from_felt_unknown() {
        assert!(ChainId::from_felt(&Felt::from(999u64)).is_err());
    }

    #[test]
    fn test_name() {
        assert_eq!(ChainId::Mainnet.name(), "SN_MAIN");
        assert_eq!(ChainId::Sepolia.name(), "SN_SEPOLIA");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", ChainId::Mainnet), "SN_MAIN");
    }
}
