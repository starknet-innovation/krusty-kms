//! Token metadata and presets for known Starknet tokens.

use crate::address::Address;
use crate::chain::ChainId;

/// ERC-20 token metadata.
#[derive(Debug, Clone)]
pub struct Token {
    pub address: Address,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

impl Token {
    /// Create a new token with all fields.
    pub fn new(
        address: Address,
        name: impl Into<String>,
        symbol: impl Into<String>,
        decimals: u8,
    ) -> Self {
        Self {
            address,
            name: name.into(),
            symbol: symbol.into(),
            decimals,
        }
    }
}

/// Well-known token presets.
pub mod presets {
    use super::*;

    // ---- Mainnet addresses ----

    const MAINNET_ETH: &str = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
    const MAINNET_STRK: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
    const MAINNET_USDC: &str = "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8";
    const MAINNET_USDT: &str = "0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8";
    const MAINNET_DAI: &str = "0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3";
    const MAINNET_WBTC: &str = "0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac";
    const MAINNET_WSTETH: &str =
        "0x042b8f0484674ca266ac5d08e4ac6a3fe65bd3129795def2dca5c34ecc5f96d2";
    const MAINNET_RETH: &str = "0x0319111a5037cbec2b3e638cc34a3474e2d2608299f3e62866e9cc683208c610";
    const MAINNET_UNI: &str = "0x049210ffc442172463f3177147c1aebc0c9677d34a20d2de4b51f9f14e99eead";
    const MAINNET_NSTR: &str = "0x04b3a82103374b4006c7a15dae5cdd76a4e1cfd1096f25e5ec0aba1f4dc63387";
    const MAINNET_LORDS: &str =
        "0x0124aeb495b947201f5fac96fd1138e326ad86195b98df6dec9009158a533b49";
    const MAINNET_EKUBO: &str =
        "0x075afe6402ad5a5c20dd25e10ec3b3986acaa647b77e4ae24b0cbc9a54a27a87";
    const MAINNET_SSTRK: &str =
        "0x0356f304b154d29d2a8fe22f1cb9107a9b564a733cf6b4cc47fd121ac1b1f95f";
    const MAINNET_NSTSTRK: &str =
        "0x04619e9ce4109590219c5263787050726be63382148538f3f936c22aa87d2fc2";
    const MAINNET_XSTRK: &str =
        "0x028d709c875c0ceac3dce7065bec5328186dc89fe254527084d1689910954b0a";

    // ---- Sepolia addresses ----

    const SEPOLIA_ETH: &str = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
    const SEPOLIA_STRK: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
    const SEPOLIA_USDC: &str = "0x053b40a647cedfca6ca84f542a0fe36736031905a9639a7f19a3c1e66bfd5080";
    const SEPOLIA_USDT: &str = "0x0386c7e15e0cf0ada26620ef4d8ea065bbb1138d656089fdfce391e9fc8e7c21";

    fn t(hex: &str, name: &str, symbol: &str, decimals: u8) -> Token {
        Token::new(Address::from_hex(hex).unwrap(), name, symbol, decimals)
    }

    /// All well-known mainnet tokens.
    pub fn mainnet_tokens() -> Vec<Token> {
        vec![
            t(MAINNET_ETH, "Ether", "ETH", 18),
            t(MAINNET_STRK, "Starknet Token", "STRK", 18),
            t(MAINNET_USDC, "USD Coin", "USDC", 6),
            t(MAINNET_USDT, "Tether USD", "USDT", 6),
            t(MAINNET_DAI, "Dai Stablecoin", "DAI", 18),
            t(MAINNET_WBTC, "Wrapped BTC", "WBTC", 8),
            t(MAINNET_WSTETH, "Wrapped stETH", "wstETH", 18),
            t(MAINNET_RETH, "Rocket Pool ETH", "rETH", 18),
            t(MAINNET_UNI, "Uniswap", "UNI", 18),
            t(MAINNET_NSTR, "Nostra", "NSTR", 18),
            t(MAINNET_LORDS, "Lords", "LORDS", 18),
            t(MAINNET_EKUBO, "Ekubo Protocol", "EKUBO", 18),
            t(MAINNET_SSTRK, "Staked STRK (Nostra)", "sSTRK", 18),
            t(MAINNET_NSTSTRK, "Nostra Staked STRK", "nstSTRK", 18),
            t(MAINNET_XSTRK, "xSTRK (Endur)", "xSTRK", 18),
        ]
    }

    /// All well-known Sepolia testnet tokens.
    pub fn sepolia_tokens() -> Vec<Token> {
        vec![
            t(SEPOLIA_ETH, "Ether", "ETH", 18),
            t(SEPOLIA_STRK, "Starknet Token", "STRK", 18),
            t(SEPOLIA_USDC, "USD Coin", "USDC", 6),
            t(SEPOLIA_USDT, "Tether USD", "USDT", 6),
        ]
    }

    /// Get the STRK token for a given chain.
    pub fn strk(chain_id: ChainId) -> Token {
        match chain_id {
            ChainId::Mainnet => t(MAINNET_STRK, "Starknet Token", "STRK", 18),
            ChainId::Sepolia => t(SEPOLIA_STRK, "Starknet Token", "STRK", 18),
        }
    }

    /// Get the ETH token for a given chain.
    pub fn eth(chain_id: ChainId) -> Token {
        match chain_id {
            ChainId::Mainnet => t(MAINNET_ETH, "Ether", "ETH", 18),
            ChainId::Sepolia => t(SEPOLIA_ETH, "Ether", "ETH", 18),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_tokens_not_empty() {
        let tokens = presets::mainnet_tokens();
        assert!(tokens.len() >= 10);
    }

    #[test]
    fn test_sepolia_tokens_not_empty() {
        let tokens = presets::sepolia_tokens();
        assert!(tokens.len() >= 2);
    }

    #[test]
    fn test_strk_preset() {
        let strk = presets::strk(ChainId::Mainnet);
        assert_eq!(strk.symbol, "STRK");
        assert_eq!(strk.decimals, 18);
    }

    #[test]
    fn test_eth_preset() {
        let eth = presets::eth(ChainId::Sepolia);
        assert_eq!(eth.symbol, "ETH");
        assert_eq!(eth.decimals, 18);
    }
}
