//! Staking validator metadata and presets.

use crate::address::Address;
use crate::chain::ChainId;

/// A staking delegation pool validator.
#[derive(Debug, Clone)]
pub struct Validator {
    pub address: Address,
    pub name: String,
}

impl Validator {
    pub fn new(address: Address, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
        }
    }
}

/// Well-known validator presets.
///
/// Pool addresses change over time — verify against the staking explorer
/// before relying on these in production.
pub mod presets {
    use super::*;

    fn v(hex: &str, name: &str) -> Validator {
        Validator::new(Address::from_hex(hex).unwrap(), name)
    }

    /// Mainnet delegation pool validators.
    pub fn mainnet_validators() -> Vec<Validator> {
        vec![
            v(
                "0x0219e985e87c0f14e5b7b1a59e05a2c1e7a248a9e18a20d665e0f16599b4e4b0",
                "Braavos",
            ),
            v(
                "0x0541dacadeb54d347a278cc5223f274e26ff916b09dd0ed87c817b47fdba1a32",
                "Argent",
            ),
            v(
                "0x06d5ee2006236e230809baa17bfe3b4ad2c663ecbf2bcab1e3a4e2d07bc35320",
                "Nethermind",
            ),
            v(
                "0x050e5d88de2b6b5d6a2e2e46e1bff55a17f6c96adead2c68d328abf99ee35b8f",
                "Voyager",
            ),
            v(
                "0x068f32ec40113e86e3c4cd7b93e46b05c4c0003beef09be4e9e3c3513fdc28de",
                "Karnot",
            ),
            v(
                "0x0478ee005a59c39d0f2cbb7fda3bb43c71a6c8ec258e82340d4eba8e35fcf434",
                "Carbonable",
            ),
            v(
                "0x01176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
                "Starknet Foundation",
            ),
            v(
                "0x0129a3e36e345f8a67e3e34dfb14de9f60c3f5d7b760920da73e38ce4cb2c55e",
                "ZKX",
            ),
        ]
    }

    /// Sepolia testnet delegation pool validators.
    ///
    /// Sepolia pools rotate frequently. Query the staking contract
    /// on-chain for current pools.
    pub fn sepolia_validators() -> Vec<Validator> {
        vec![]
    }

    /// Get validators for a given chain.
    pub fn validators(chain_id: ChainId) -> Vec<Validator> {
        match chain_id {
            ChainId::Mainnet => mainnet_validators(),
            ChainId::Sepolia => sepolia_validators(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_validators_not_empty() {
        let vals = presets::mainnet_validators();
        assert!(!vals.is_empty());
    }

    #[test]
    fn test_sepolia_validators_empty() {
        let vals = presets::sepolia_validators();
        assert!(vals.is_empty());
    }

    #[test]
    fn test_validators_by_chain() {
        let vals = presets::validators(ChainId::Mainnet);
        assert!(!vals.is_empty());
    }
}
