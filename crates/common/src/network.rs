//! Network preset configuration for Starknet chains.

use crate::address::Address;
use crate::chain::ChainId;

/// A preset configuration for a Starknet network.
#[derive(Debug, Clone)]
pub struct NetworkPreset {
    pub chain_id: ChainId,
    pub rpc_url: String,
    pub explorer_base_url: String,
    pub name: String,
}

impl NetworkPreset {
    /// Starknet Mainnet defaults.
    pub fn mainnet() -> Self {
        Self {
            chain_id: ChainId::Mainnet,
            rpc_url: "https://api.cartridge.gg/x/starknet/mainnet".into(),
            explorer_base_url: "https://voyager.online".into(),
            name: "Starknet Mainnet".into(),
        }
    }

    /// Starknet Sepolia testnet defaults.
    pub fn sepolia() -> Self {
        Self {
            chain_id: ChainId::Sepolia,
            rpc_url: "https://api.cartridge.gg/x/starknet/sepolia".into(),
            explorer_base_url: "https://sepolia.voyager.online".into(),
            name: "Starknet Sepolia".into(),
        }
    }

    /// Local devnet defaults.
    pub fn devnet() -> Self {
        Self {
            chain_id: ChainId::Sepolia,
            rpc_url: "http://127.0.0.1:5050".into(),
            explorer_base_url: "http://localhost:3000".into(),
            name: "Devnet".into(),
        }
    }

    /// Build an explorer URL for a transaction hash.
    pub fn explorer_tx_url(&self, hash: &str) -> String {
        format!("{}/tx/{}", self.explorer_base_url, hash)
    }

    /// Build an explorer URL for a contract address.
    pub fn explorer_contract_url(&self, address: &Address) -> String {
        format!("{}/contract/{}", self.explorer_base_url, address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_preset() {
        let net = NetworkPreset::mainnet();
        assert_eq!(net.chain_id, ChainId::Mainnet);
        assert!(net.rpc_url.contains("mainnet"));
    }

    #[test]
    fn test_sepolia_preset() {
        let net = NetworkPreset::sepolia();
        assert_eq!(net.chain_id, ChainId::Sepolia);
        assert!(net.rpc_url.contains("sepolia"));
    }

    #[test]
    fn test_explorer_tx_url() {
        let net = NetworkPreset::mainnet();
        let url = net.explorer_tx_url("0xabc");
        assert_eq!(url, "https://voyager.online/tx/0xabc");
    }

    #[test]
    fn test_explorer_contract_url() {
        let net = NetworkPreset::mainnet();
        let addr = Address::from_hex("0x123").unwrap();
        let url = net.explorer_contract_url(&addr);
        assert!(url.starts_with("https://voyager.online/contract/"));
    }
}
