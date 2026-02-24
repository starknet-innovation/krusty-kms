//! Vesu money market adapter (V1.1 Singleton architecture).
//!
//! Provides deposit/withdraw through vToken ERC-4626 contracts.
//! vTokens wrap Vesu lending positions into a standard vault interface.

use crate::abi;
use crate::tx::Tx;
use crate::wallet::utils::core_felt_to_rs;
use crate::wallet::WalletExecutor;
use krusty_kms_common::address::Address;
use krusty_kms_common::amount::Amount;
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::{KmsError, Result};
use std::sync::Arc;
use starknet_rust::core::types::{BlockId, BlockTag, Call, FunctionCall};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;

// ---------------------------------------------------------------------------
// V1.1 Singleton addresses
// ---------------------------------------------------------------------------

const SINGLETON_MAINNET: &str =
    "0x000d8d6dfec4d33bfb6895de9f3852143a17c6f92fd2a21da3d6924d34870160";
const SINGLETON_SEPOLIA: &str =
    "0x2110b3cde727cd34407e257e1070857a06010cf02a14b1ee181612fb1b61c30";

// ---------------------------------------------------------------------------
// V1.1 Extension (ExtensionPOV2) addresses — manages vTokens
// ---------------------------------------------------------------------------

const EXTENSION_MAINNET: &str =
    "0x4e06e04b8d624d039aa1c3ca8e0aa9e21dc1ccba1d88d0d650837159e0ee054";
const EXTENSION_SEPOLIA: &str =
    "0x274669f178d303cdd92638ab2aee6d5cb75d72baf79606a02b719a6fb388c0";

// ---------------------------------------------------------------------------
// Default pool IDs (Genesis pool)
// ---------------------------------------------------------------------------

const DEFAULT_POOL_ID_MAINNET: &str =
    "0x4dc4f0ca6ea4961e4c8373265bfd5317678f4fe374d76f3fd7135f57763bf28";
const DEFAULT_POOL_ID_SEPOLIA: &str =
    "0x4dc4f0ca6ea4961e4c8373265bfd5317678f4fe374d76f3fd7135f57763bf28";

/// Vesu money market adapter.
pub struct Vesu {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    chain_id: ChainId,
    singleton: Address,
    extension: Address,
    default_pool_id: starknet_types_core::felt::Felt,
}

impl Vesu {
    /// Create a new Vesu adapter for the given chain.
    pub fn new(provider: Arc<JsonRpcClient<HttpTransport>>, chain_id: ChainId) -> Self {
        let (singleton, extension, pool_id) = match chain_id {
            ChainId::Mainnet => (
                Address::from_hex(SINGLETON_MAINNET).unwrap(),
                Address::from_hex(EXTENSION_MAINNET).unwrap(),
                starknet_types_core::felt::Felt::from_hex(DEFAULT_POOL_ID_MAINNET).unwrap(),
            ),
            ChainId::Sepolia => (
                Address::from_hex(SINGLETON_SEPOLIA).unwrap(),
                Address::from_hex(EXTENSION_SEPOLIA).unwrap(),
                starknet_types_core::felt::Felt::from_hex(DEFAULT_POOL_ID_SEPOLIA).unwrap(),
            ),
        };

        Self {
            provider,
            chain_id,
            singleton,
            extension,
            default_pool_id: pool_id,
        }
    }

    /// Resolve the vToken address for a given asset in the default Vesu pool.
    ///
    /// Queries the Extension contract's `v_token` method.
    pub async fn get_vtoken_for_asset(
        &self,
        asset: &Address,
        pool_id: Option<&starknet_types_core::felt::Felt>,
    ) -> Result<Address> {
        let pool_id = pool_id.unwrap_or(&self.default_pool_id);
        let extension_rs = core_felt_to_rs(self.extension.as_felt());
        let pool_id_rs = core_felt_to_rs(*pool_id);
        let asset_rs = core_felt_to_rs(asset.as_felt());

        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: extension_rs,
                    entry_point_selector: *abi::vesu::V_TOKEN,
                    calldata: vec![pool_id_rs, asset_rs],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| KmsError::RpcError(format!("Vesu vToken query failed: {e}")))?;

        if result.is_empty() {
            return Err(KmsError::RpcError(
                "Empty response from Vesu vToken query".into(),
            ));
        }

        let vtoken_felt =
            crate::wallet::utils::rs_felt_to_core(result[0]);

        if vtoken_felt == starknet_types_core::felt::Felt::ZERO {
            return Err(KmsError::RpcError(format!(
                "No vToken found for asset {}",
                asset
            )));
        }

        Ok(Address::from(vtoken_felt))
    }

    /// Build calls for a Vesu deposit via vToken (ERC-4626).
    ///
    /// Returns 2 calls:
    /// 1. `approve(vtoken, amount)` on the asset token
    /// 2. `deposit(amount, receiver)` on the vToken
    pub fn populate_deposit(
        &self,
        asset: &Address,
        vtoken: &Address,
        amount: &Amount,
        receiver: &Address,
    ) -> Vec<Call> {
        let (low, high) = amount.to_u256();
        let asset_rs = core_felt_to_rs(asset.as_felt());
        let vtoken_rs = core_felt_to_rs(vtoken.as_felt());
        let receiver_rs = core_felt_to_rs(receiver.as_felt());

        let approve = Call {
            to: asset_rs,
            selector: *abi::erc20::APPROVE,
            calldata: vec![
                vtoken_rs,
                core_felt_to_rs(low),
                core_felt_to_rs(high),
            ],
        };

        let deposit = Call {
            to: vtoken_rs,
            selector: *abi::vesu::DEPOSIT,
            calldata: vec![
                core_felt_to_rs(low),
                core_felt_to_rs(high),
                receiver_rs,
            ],
        };

        vec![approve, deposit]
    }

    /// Build a call for a Vesu withdraw via vToken (ERC-4626).
    ///
    /// Calls `withdraw(assets, receiver, owner)` on the vToken.
    pub fn populate_withdraw(
        &self,
        vtoken: &Address,
        amount: &Amount,
        receiver: &Address,
        owner: &Address,
    ) -> Call {
        let (low, high) = amount.to_u256();
        let vtoken_rs = core_felt_to_rs(vtoken.as_felt());

        Call {
            to: vtoken_rs,
            selector: *abi::vesu::WITHDRAW,
            calldata: vec![
                core_felt_to_rs(low),
                core_felt_to_rs(high),
                core_felt_to_rs(receiver.as_felt()),
                core_felt_to_rs(owner.as_felt()),
            ],
        }
    }

    /// Execute a deposit through a wallet.
    ///
    /// Approves the vToken to spend the asset, then deposits.
    pub async fn deposit(
        &self,
        wallet: &dyn WalletExecutor,
        asset: &Address,
        vtoken: &Address,
        amount: &Amount,
    ) -> Result<Tx> {
        let calls = self.populate_deposit(asset, vtoken, amount, wallet.address());
        wallet.execute(calls).await
    }

    /// Execute a withdraw through a wallet.
    ///
    /// Withdraws assets from the vToken to the wallet.
    pub async fn withdraw(
        &self,
        wallet: &dyn WalletExecutor,
        vtoken: &Address,
        amount: &Amount,
    ) -> Result<Tx> {
        let call =
            self.populate_withdraw(vtoken, amount, wallet.address(), wallet.address());
        wallet.execute(vec![call]).await
    }

    /// The Vesu Singleton address for this chain.
    pub fn singleton(&self) -> &Address {
        &self.singleton
    }

    /// The Vesu Extension address for this chain.
    pub fn extension(&self) -> &Address {
        &self.extension
    }

    /// The default pool ID.
    pub fn default_pool_id(&self) -> &starknet_types_core::felt::Felt {
        &self.default_pool_id
    }

    /// The chain ID.
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider() -> Arc<JsonRpcClient<HttpTransport>> {
        Arc::new(JsonRpcClient::new(
            starknet_rust::providers::jsonrpc::HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap(),
            ),
        ))
    }

    #[test]
    fn test_new_mainnet() {
        let provider = make_provider();
        let vesu = Vesu::new(provider, ChainId::Mainnet);
        assert_ne!(vesu.singleton().as_felt(), starknet_types_core::felt::Felt::ZERO);
        assert_ne!(vesu.extension().as_felt(), starknet_types_core::felt::Felt::ZERO);
    }

    #[test]
    fn test_new_sepolia() {
        let provider = make_provider();
        let vesu = Vesu::new(provider, ChainId::Sepolia);
        assert_ne!(vesu.singleton().as_felt(), starknet_types_core::felt::Felt::ZERO);
    }

    #[test]
    fn test_different_chains_different_addresses() {
        let p1 = make_provider();
        let p2 = make_provider();
        let mainnet = Vesu::new(p1, ChainId::Mainnet);
        let sepolia = Vesu::new(p2, ChainId::Sepolia);
        assert_ne!(
            mainnet.singleton().as_felt(),
            sepolia.singleton().as_felt()
        );
    }

    #[test]
    fn test_populate_deposit_returns_2_calls() {
        let provider = make_provider();
        let vesu = Vesu::new(provider, ChainId::Mainnet);

        let asset = Address::from_hex(
            "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
        )
        .unwrap(); // ETH
        let vtoken = Address::from_hex("0xABC").unwrap();
        let amount = Amount::from_raw(1_000_000_000_000_000_000, 18); // 1 ETH
        let receiver = Address::from_hex("0xDEF").unwrap();

        let calls = vesu.populate_deposit(&asset, &vtoken, &amount, &receiver);
        assert_eq!(calls.len(), 2);

        // First call is approve on the asset
        assert_eq!(calls[0].to, core_felt_to_rs(asset.as_felt()));
        assert_eq!(calls[0].selector, *abi::erc20::APPROVE);
        // approve calldata: [spender, low, high] = 3
        assert_eq!(calls[0].calldata.len(), 3);

        // Second call is deposit on the vToken
        assert_eq!(calls[1].to, core_felt_to_rs(vtoken.as_felt()));
        assert_eq!(calls[1].selector, *abi::vesu::DEPOSIT);
        // deposit calldata: [amount_low, amount_high, receiver] = 3
        assert_eq!(calls[1].calldata.len(), 3);
    }

    #[test]
    fn test_populate_withdraw() {
        let provider = make_provider();
        let vesu = Vesu::new(provider, ChainId::Mainnet);

        let vtoken = Address::from_hex("0xABC").unwrap();
        let amount = Amount::from_raw(500_000_000_000_000_000, 18); // 0.5
        let receiver = Address::from_hex("0xDEF").unwrap();
        let owner = Address::from_hex("0x111").unwrap();

        let call = vesu.populate_withdraw(&vtoken, &amount, &receiver, &owner);
        assert_eq!(call.to, core_felt_to_rs(vtoken.as_felt()));
        assert_eq!(call.selector, *abi::vesu::WITHDRAW);
        // withdraw calldata: [amount_low, amount_high, receiver, owner] = 4
        assert_eq!(call.calldata.len(), 4);
    }
}
