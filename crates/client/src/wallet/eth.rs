//! Ethereum-key wallet for secp256k1-signed Starknet accounts.
//!
//! Uses raw V3 transaction building because `starknet-rust`'s `Signer` trait
//! returns `Signature { r, s }` (2 Stark Felts) while Ethereum accounts need
//! a 5-Felt signature: `[r_low, r_high, s_low, s_high, v]`.

use super::utils::{check_deployed, core_felt_to_rs, rs_felt_to_core, StarknetRsFelt};
use super::WalletExecutor;
use crate::tx::encode::encode_execute_calldata;
use crate::tx::hash::{
    compute_deploy_account_v3_hash, compute_invoke_v3_hash, DaMode, ResourceBounds,
};
use crate::tx::Tx;
use krusty_kms::account_class::OpenZeppelinEthAccount;
use krusty_kms::AccountClass;
use krusty_kms::EthSigner;
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::network::NetworkPreset;
use krusty_kms_common::{KmsError, Result};
use std::sync::Arc;
use std::time::Instant;
use starknet_rust::core::types::{
    BlockId, BlockTag, BroadcastedDeployAccountTransactionV3,
    BroadcastedInvokeTransactionV3, BroadcastedTransaction, Call, DataAvailabilityMode,
    FeeEstimate, ResourceBoundsMapping, SimulationFlagForEstimateFee,
};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;
use starknet_types_core::felt::Felt as CoreFelt;
use tokio::sync::RwLock;

/// Cache TTL for the "not deployed" state (3 seconds).
const DEPLOYED_CACHE_TTL_SECS: u64 = 3;

/// Fee estimation safety multiplier (numerator / denominator).
const FEE_MARGIN_NUM: u64 = 3;
const FEE_MARGIN_DEN: u64 = 2;

/// A Starknet wallet using secp256k1 (Ethereum) signing.
///
/// Builds V3 transactions manually since `SingleOwnerAccount` cannot produce
/// the 5-Felt secp256k1 signature format required by OZ Ethereum accounts.
pub struct EthWallet {
    signer: EthSigner,
    provider: Arc<JsonRpcClient<HttpTransport>>,
    address: Address,
    chain_id: ChainId,
    network: NetworkPreset,
    // Precomputed deployment data (CoreFelt for hash computation).
    class_hash: CoreFelt,
    constructor_calldata: Vec<CoreFelt>,
    salt: CoreFelt,
    deployed_cache: RwLock<Option<(bool, Instant)>>,
}

impl EthWallet {
    /// Create from a raw 32-byte Ethereum private key.
    ///
    /// Uses the default OZ Ethereum Account class hash.
    pub fn new(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        private_key: &[u8; 32],
        chain_id: ChainId,
        network: NetworkPreset,
    ) -> Result<Self> {
        let account_class = OpenZeppelinEthAccount::new();
        Self::with_class(provider, private_key, &account_class, chain_id, network)
    }

    /// Create from a hex-encoded private key (with or without `0x` prefix).
    pub fn from_hex(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        hex_key: &str,
        chain_id: ChainId,
        network: NetworkPreset,
    ) -> Result<Self> {
        let signer = EthSigner::from_hex(hex_key)?;
        let account_class = OpenZeppelinEthAccount::new();
        Self::from_signer(provider, signer, &account_class, chain_id, network)
    }

    /// Create with a custom account class.
    pub fn with_class(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        private_key: &[u8; 32],
        account_class: &OpenZeppelinEthAccount,
        chain_id: ChainId,
        network: NetworkPreset,
    ) -> Result<Self> {
        let signer = EthSigner::from_private_key(private_key)?;
        Self::from_signer(provider, signer, account_class, chain_id, network)
    }

    fn from_signer(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        signer: EthSigner,
        account_class: &OpenZeppelinEthAccount,
        chain_id: ChainId,
        network: NetworkPreset,
    ) -> Result<Self> {
        let (x, y) = signer.public_key_xy();
        let class_hash = account_class.class_hash();
        let constructor_calldata = account_class.build_constructor_calldata_eth(&x, &y);
        let salt = account_class.get_salt_eth(&x, &y);
        let address_felt = account_class.calculate_address_eth(&x, &y)?;
        let address = Address::from(address_felt);

        Ok(Self {
            signer,
            provider,
            address,
            chain_id,
            network,
            class_hash,
            constructor_calldata,
            salt,
            deployed_cache: RwLock::new(None),
        })
    }

    /// Deploy this account on-chain (user pays gas).
    ///
    /// Sends a `DeployAccountTransactionV3` with the secp256k1 signature.
    pub async fn deploy(&self) -> Result<Tx> {
        let deployed = self.is_deployed().await?;
        if deployed {
            return Err(KmsError::TransactionError(
                "Account is already deployed".into(),
            ));
        }

        let nonce = CoreFelt::ZERO; // deploy nonce is always 0
        let chain_id_core = self.chain_id.as_felt();

        // Convert deployment data to StarknetRsFelt for the broadcasted tx.
        let class_hash_rs = core_felt_to_rs(self.class_hash);
        let salt_rs = core_felt_to_rs(self.salt);
        let constructor_calldata_rs: Vec<StarknetRsFelt> = self
            .constructor_calldata
            .iter()
            .map(|f| core_felt_to_rs(*f))
            .collect();

        // Estimate fees with a dummy deploy tx.
        let dummy_sig = vec![StarknetRsFelt::ZERO; 5];
        let dummy_deploy = BroadcastedDeployAccountTransactionV3 {
            signature: dummy_sig,
            nonce: StarknetRsFelt::ZERO,
            contract_address_salt: salt_rs,
            constructor_calldata: constructor_calldata_rs.clone(),
            class_hash: class_hash_rs,
            resource_bounds: zero_resource_bounds(),
            tip: 0,
            paymaster_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: true,
        };

        let estimates = self
            .provider
            .estimate_fee(
                &[BroadcastedTransaction::DeployAccount(dummy_deploy)],
                vec![SimulationFlagForEstimateFee::SkipValidate],
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| KmsError::FeeEstimationFailed(e.to_string()))?;

        let estimate = estimates
            .first()
            .ok_or_else(|| KmsError::FeeEstimationFailed("empty estimate".into()))?;

        let resource_bounds = estimate_to_resource_bounds(estimate);

        // Compute the deploy-account transaction hash.
        let (l1_gas, l2_gas) = mapping_to_hash_bounds(&resource_bounds);
        let address_core = self.address.as_felt();

        let tx_hash = compute_deploy_account_v3_hash(
            &address_core,
            &self.class_hash,
            &self.constructor_calldata,
            &self.salt,
            &chain_id_core,
            &nonce,
            0,
            &l1_gas,
            &l2_gas,
            &[], // paymaster_data
            DaMode::L1,
            DaMode::L1,
        );

        // Sign with secp256k1.
        let sig_felts = self.signer.sign_hash(&tx_hash)?;
        let signature: Vec<StarknetRsFelt> =
            sig_felts.iter().map(|f| core_felt_to_rs(*f)).collect();

        // Build and submit the deploy-account transaction.
        let deploy_tx = BroadcastedDeployAccountTransactionV3 {
            signature,
            nonce: StarknetRsFelt::ZERO,
            contract_address_salt: salt_rs,
            constructor_calldata: constructor_calldata_rs,
            class_hash: class_hash_rs,
            resource_bounds,
            tip: 0,
            paymaster_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };

        let result = self
            .provider
            .add_deploy_account_transaction(&deploy_tx)
            .await
            .map_err(|e| KmsError::TransactionError(e.to_string()))?;

        // Invalidate deployment cache.
        {
            let mut cache = self.deployed_cache.write().await;
            *cache = None;
        }

        Ok(Tx::new(
            result.transaction_hash,
            self.provider.clone(),
            self.network.clone(),
        ))
    }

    /// Deploy if not already deployed. Returns `None` if already deployed.
    pub async fn ensure_deployed(&self) -> Result<Option<Tx>> {
        if self.is_deployed().await? {
            Ok(None)
        } else {
            Ok(Some(self.deploy().await?))
        }
    }

    /// The underlying `EthSigner`.
    pub fn signer(&self) -> &EthSigner {
        &self.signer
    }

    /// The account class hash.
    pub fn class_hash(&self) -> CoreFelt {
        self.class_hash
    }

    /// The underlying JSON-RPC provider.
    pub fn provider(&self) -> &Arc<JsonRpcClient<HttpTransport>> {
        &self.provider
    }

    /// Start building a batched transaction.
    pub fn tx(&self) -> crate::tx::TxBuilder<'_> {
        crate::tx::TxBuilder::new(self)
    }

    /// Check whether the account contract is deployed on-chain.
    async fn check_deployed(&self) -> Result<bool> {
        {
            let cache = self.deployed_cache.read().await;
            if let Some((deployed, ts)) = *cache {
                if deployed || ts.elapsed().as_secs() < DEPLOYED_CACHE_TTL_SECS {
                    return Ok(deployed);
                }
            }
        }

        let address_rs = core_felt_to_rs(self.address.as_felt());
        let deployed = check_deployed(&self.provider, address_rs).await?;

        {
            let mut cache = self.deployed_cache.write().await;
            *cache = Some((deployed, Instant::now()));
        }

        Ok(deployed)
    }

    /// Execute a list of calls as a single V3 invoke transaction.
    async fn execute_inner(&self, calls: Vec<Call>) -> Result<Tx> {
        let calldata = encode_execute_calldata(&calls);
        let address_rs = core_felt_to_rs(self.address.as_felt());
        let chain_id_core = self.chain_id.as_felt();

        // Get nonce.
        let nonce_rs = self
            .provider
            .get_nonce(BlockId::Tag(BlockTag::Latest), address_rs)
            .await
            .map_err(|e| KmsError::RpcError(e.to_string()))?;

        let nonce_core = rs_felt_to_core(nonce_rs);

        // Estimate fees with dummy signature.
        let dummy_sig = vec![StarknetRsFelt::ZERO; 5];
        let dummy_tx = BroadcastedInvokeTransactionV3 {
            sender_address: address_rs,
            calldata: calldata.clone(),
            signature: dummy_sig,
            nonce: nonce_rs,
            resource_bounds: zero_resource_bounds(),
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: true,
        };

        let estimates = self
            .provider
            .estimate_fee(
                &[BroadcastedTransaction::Invoke(dummy_tx)],
                vec![SimulationFlagForEstimateFee::SkipValidate],
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| KmsError::FeeEstimationFailed(e.to_string()))?;

        let estimate = estimates
            .first()
            .ok_or_else(|| KmsError::FeeEstimationFailed("empty estimate".into()))?;

        let resource_bounds = estimate_to_resource_bounds(estimate);

        // Convert calldata to CoreFelt for hash computation.
        let calldata_core: Vec<CoreFelt> =
            calldata.iter().map(|f| rs_felt_to_core(*f)).collect();

        let (l1_gas, l2_gas) = mapping_to_hash_bounds(&resource_bounds);
        let address_core = self.address.as_felt();

        let tx_hash = compute_invoke_v3_hash(
            &address_core,
            &calldata_core,
            &chain_id_core,
            &nonce_core,
            0,
            &l1_gas,
            &l2_gas,
            &[], // paymaster_data
            &[], // account_deployment_data
            DaMode::L1,
            DaMode::L1,
        );

        // Sign with secp256k1.
        let sig_felts = self.signer.sign_hash(&tx_hash)?;
        let signature: Vec<StarknetRsFelt> =
            sig_felts.iter().map(|f| core_felt_to_rs(*f)).collect();

        // Build and submit the invoke transaction.
        let invoke_tx = BroadcastedInvokeTransactionV3 {
            sender_address: address_rs,
            calldata,
            signature,
            nonce: nonce_rs,
            resource_bounds,
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };

        let result = self
            .provider
            .add_invoke_transaction(&invoke_tx)
            .await
            .map_err(|e| KmsError::TransactionError(e.to_string()))?;

        Ok(Tx::new(
            result.transaction_hash,
            self.provider.clone(),
            self.network.clone(),
        ))
    }

    /// Estimate fees for a list of calls.
    async fn estimate_fee_inner(&self, calls: Vec<Call>) -> Result<FeeEstimate> {
        let calldata = encode_execute_calldata(&calls);
        let address_rs = core_felt_to_rs(self.address.as_felt());

        let nonce_rs = self
            .provider
            .get_nonce(BlockId::Tag(BlockTag::Latest), address_rs)
            .await
            .map_err(|e| KmsError::RpcError(e.to_string()))?;

        let dummy_sig = vec![StarknetRsFelt::ZERO; 5];
        let dummy_tx = BroadcastedInvokeTransactionV3 {
            sender_address: address_rs,
            calldata,
            signature: dummy_sig,
            nonce: nonce_rs,
            resource_bounds: zero_resource_bounds(),
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: true,
        };

        let estimates = self
            .provider
            .estimate_fee(
                &[BroadcastedTransaction::Invoke(dummy_tx)],
                vec![SimulationFlagForEstimateFee::SkipValidate],
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| KmsError::FeeEstimationFailed(e.to_string()))?;

        estimates
            .into_iter()
            .next()
            .ok_or_else(|| KmsError::FeeEstimationFailed("empty estimate".into()))
    }
}

#[async_trait::async_trait]
impl WalletExecutor for EthWallet {
    async fn execute(&self, calls: Vec<Call>) -> Result<Tx> {
        self.execute_inner(calls).await
    }

    async fn estimate_fee(&self, calls: Vec<Call>) -> Result<FeeEstimate> {
        self.estimate_fee_inner(calls).await
    }

    fn address(&self) -> &Address {
        &self.address
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn network(&self) -> &NetworkPreset {
        &self.network
    }

    async fn is_deployed(&self) -> Result<bool> {
        self.check_deployed().await
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create zero resource bounds (used for fee estimation queries).
fn zero_resource_bounds() -> ResourceBoundsMapping {
    ResourceBoundsMapping {
        l1_gas: starknet_rust::core::types::ResourceBounds {
            max_amount: 0,
            max_price_per_unit: 0,
        },
        l1_data_gas: starknet_rust::core::types::ResourceBounds {
            max_amount: 0,
            max_price_per_unit: 0,
        },
        l2_gas: starknet_rust::core::types::ResourceBounds {
            max_amount: 0,
            max_price_per_unit: 0,
        },
    }
}

/// Convert a `FeeEstimate` into `ResourceBoundsMapping` with safety margins.
fn estimate_to_resource_bounds(estimate: &FeeEstimate) -> ResourceBoundsMapping {
    ResourceBoundsMapping {
        l1_gas: starknet_rust::core::types::ResourceBounds {
            max_amount: estimate
                .l1_gas_consumed
                .saturating_mul(FEE_MARGIN_NUM)
                / FEE_MARGIN_DEN,
            max_price_per_unit: estimate
                .l1_gas_price
                .saturating_mul(FEE_MARGIN_NUM as u128)
                / FEE_MARGIN_DEN as u128,
        },
        l1_data_gas: starknet_rust::core::types::ResourceBounds {
            max_amount: estimate
                .l1_data_gas_consumed
                .saturating_mul(FEE_MARGIN_NUM)
                / FEE_MARGIN_DEN,
            max_price_per_unit: estimate
                .l1_data_gas_price
                .saturating_mul(FEE_MARGIN_NUM as u128)
                / FEE_MARGIN_DEN as u128,
        },
        l2_gas: starknet_rust::core::types::ResourceBounds {
            max_amount: estimate
                .l2_gas_consumed
                .saturating_mul(FEE_MARGIN_NUM)
                / FEE_MARGIN_DEN,
            max_price_per_unit: estimate
                .l2_gas_price
                .saturating_mul(FEE_MARGIN_NUM as u128)
                / FEE_MARGIN_DEN as u128,
        },
    }
}

/// Convert `ResourceBoundsMapping` to the hash module's `ResourceBounds` type.
fn mapping_to_hash_bounds(
    mapping: &ResourceBoundsMapping,
) -> (ResourceBounds, ResourceBounds) {
    (
        ResourceBounds {
            max_amount: mapping.l1_gas.max_amount,
            max_price_per_unit: mapping.l1_gas.max_price_per_unit,
        },
        ResourceBounds {
            max_amount: mapping.l2_gas.max_amount,
            max_price_per_unit: mapping.l2_gas.max_price_per_unit,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_HEX: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn make_provider() -> Arc<JsonRpcClient<HttpTransport>> {
        Arc::new(JsonRpcClient::new(
            starknet_rust::providers::jsonrpc::HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap(),
            ),
        ))
    }

    #[test]
    fn test_factory_computes_address() {
        let provider = make_provider();
        let wallet = EthWallet::from_hex(
            provider,
            TEST_KEY_HEX,
            ChainId::Sepolia,
            NetworkPreset::sepolia(),
        )
        .unwrap();

        assert_ne!(wallet.address().as_felt(), CoreFelt::ZERO);
    }

    #[test]
    fn test_factory_deterministic() {
        let provider1 = make_provider();
        let wallet1 = EthWallet::from_hex(
            provider1,
            TEST_KEY_HEX,
            ChainId::Sepolia,
            NetworkPreset::sepolia(),
        )
        .unwrap();

        let provider2 = make_provider();
        let wallet2 = EthWallet::from_hex(
            provider2,
            TEST_KEY_HEX,
            ChainId::Sepolia,
            NetworkPreset::sepolia(),
        )
        .unwrap();

        assert_eq!(wallet1.address(), wallet2.address());
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let provider1 = make_provider();
        let wallet1 = EthWallet::from_hex(
            provider1,
            TEST_KEY_HEX,
            ChainId::Sepolia,
            NetworkPreset::sepolia(),
        )
        .unwrap();

        let provider2 = make_provider();
        let wallet2 = EthWallet::from_hex(
            provider2,
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
            ChainId::Sepolia,
            NetworkPreset::sepolia(),
        )
        .unwrap();

        assert_ne!(wallet1.address(), wallet2.address());
    }

    #[test]
    fn test_class_hash_matches_oz_eth() {
        let provider = make_provider();
        let wallet = EthWallet::from_hex(
            provider,
            TEST_KEY_HEX,
            ChainId::Sepolia,
            NetworkPreset::sepolia(),
        )
        .unwrap();
        let expected = CoreFelt::from_hex(OpenZeppelinEthAccount::CLASS_HASH).unwrap();
        assert_eq!(wallet.class_hash(), expected);
    }

    #[test]
    fn test_zero_resource_bounds() {
        let bounds = zero_resource_bounds();
        assert_eq!(bounds.l1_gas.max_amount, 0);
        assert_eq!(bounds.l2_gas.max_amount, 0);
    }

    #[test]
    fn test_estimate_to_resource_bounds_applies_margin() {
        let estimate = FeeEstimate {
            l1_gas_consumed: 100,
            l1_gas_price: 1000,
            l2_gas_consumed: 200,
            l2_gas_price: 2000,
            l1_data_gas_consumed: 50,
            l1_data_gas_price: 500,
            overall_fee: 999999,
        };
        let bounds = estimate_to_resource_bounds(&estimate);

        // 100 * 3 / 2 = 150
        assert_eq!(bounds.l1_gas.max_amount, 150);
        assert_eq!(bounds.l1_gas.max_price_per_unit, 1500);
        assert_eq!(bounds.l2_gas.max_amount, 300);
        assert_eq!(bounds.l2_gas.max_price_per_unit, 3000);
        assert_eq!(bounds.l1_data_gas.max_amount, 75);
        assert_eq!(bounds.l1_data_gas.max_price_per_unit, 750);
    }
}
