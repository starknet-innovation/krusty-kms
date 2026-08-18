//! Wallet: owns a provider + account, can sign and execute transactions.

pub mod deploy;
pub mod utils;

use krusty_kms::{AccountClass, SaltPolicy};
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::fee::{FeeBounds, FeeEstimateInput, ResolvedFeeBounds};
use krusty_kms_common::network::NetworkPreset;
use krusty_kms_common::{KmsError, Result};
use krusty_kms_wallet_api::Tx;
pub use krusty_kms_wallet_api::WalletExecutor;
use starknet_rust::accounts::{ExecutionEncoding, SingleOwnerAccount};
use starknet_rust::core::types::Call;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::signers::{LocalWallet, SigningKey};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use self::utils::{check_deployed, core_felt_to_rs};

/// A Starknet wallet that can sign and submit transactions.
pub struct Wallet {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    account: SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>,
    address: Address,
    chain_id: ChainId,
    network: NetworkPreset,
    fee_bounds: FeeBounds,
    deployed_cache: RwLock<Option<(bool, Instant)>>,
}

/// Cache TTL for the "not deployed" state (3 seconds).
const DEPLOYED_CACHE_TTL_SECS: u64 = 3;

impl Wallet {
    /// Create a wallet from a `SigningKey`.
    ///
    /// This is the main factory method. It uses the given `AccountClass` to compute
    /// the expected deployment address from the signing key's public key and the
    /// explicit `salt_policy`.
    pub fn from_signing_key(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        signing_key: SigningKey,
        account_class: &dyn AccountClass,
        salt_policy: SaltPolicy,
        chain_id: ChainId,
        network: NetworkPreset,
    ) -> Result<Self> {
        let verifying_key = signing_key.verifying_key();
        let public_key_rs = verifying_key.scalar();
        let public_key_core = utils::rs_felt_to_core(public_key_rs);

        let address_felt = account_class.calculate_address(&public_key_core, salt_policy)?;
        let address = Address::from(address_felt);
        let address_rs = core_felt_to_rs(address_felt);
        let chain_id_rs = core_felt_to_rs(chain_id.as_felt());

        let signer = LocalWallet::from(signing_key);
        let account = SingleOwnerAccount::new(
            provider.clone(),
            signer,
            address_rs,
            chain_id_rs,
            ExecutionEncoding::New,
        );

        Ok(Self {
            provider,
            account,
            address,
            chain_id,
            network,
            fee_bounds: FeeBounds::default(),
            deployed_cache: RwLock::new(None),
        })
    }

    /// Create a wallet for an already-deployed account at a known address.
    ///
    /// This constructor is useful for devnet predeployed accounts, imported
    /// accounts, and external deployment flows where the account address is
    /// known and should not be recomputed from a local [`AccountClass`].
    pub fn from_signing_key_at_address(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        signing_key: SigningKey,
        address: Address,
        chain_id: ChainId,
        network: NetworkPreset,
    ) -> Self {
        let signer = LocalWallet::from(signing_key);
        let account = SingleOwnerAccount::new(
            provider.clone(),
            signer,
            core_felt_to_rs(address.as_felt()),
            core_felt_to_rs(chain_id.as_felt()),
            ExecutionEncoding::New,
        );

        Self {
            provider,
            account,
            address,
            chain_id,
            network,
            fee_bounds: FeeBounds::default(),
            deployed_cache: RwLock::new(None),
        }
    }

    /// Convenience: create from a private key Felt.
    pub fn from_private_key(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        private_key: starknet_types_core::felt::Felt,
        account_class: &dyn AccountClass,
        salt_policy: SaltPolicy,
        chain_id: ChainId,
        network: NetworkPreset,
    ) -> Result<Self> {
        let pk_rs = core_felt_to_rs(private_key);
        let signing_key = SigningKey::from_secret_scalar(pk_rs);
        Self::from_signing_key(
            provider,
            signing_key,
            account_class,
            salt_policy,
            chain_id,
            network,
        )
    }

    /// Convenience: create from a private key and known account address.
    pub fn from_private_key_at_address(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        private_key: starknet_types_core::felt::Felt,
        address: Address,
        chain_id: ChainId,
        network: NetworkPreset,
    ) -> Self {
        let pk_rs = core_felt_to_rs(private_key);
        let signing_key = SigningKey::from_secret_scalar(pk_rs);
        Self::from_signing_key_at_address(provider, signing_key, address, chain_id, network)
    }

    /// Check whether the account contract is deployed on-chain.
    ///
    /// Caches a negative result for 3 seconds to avoid hammering the RPC.
    pub async fn is_deployed(&self) -> Result<bool> {
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

    /// Replace the fee bounds this wallet signs within.
    ///
    /// Defaults to [`FeeBounds::default`], which pins the tip to zero and caps
    /// the total at [`krusty_kms_common::fee::DEFAULT_MAX_FEE_FRI`].
    #[must_use]
    pub fn with_fee_bounds(mut self, fee_bounds: FeeBounds) -> Self {
        self.fee_bounds = fee_bounds;
        self
    }

    /// The fee bounds applied to every transaction this wallet sends.
    pub fn fee_bounds(&self) -> &FeeBounds {
        &self.fee_bounds
    }

    /// Execute a list of calls via `execute_v3`.
    ///
    /// Every V3 fee field is pinned before signing rather than left for the RPC
    /// endpoint to fill: the tip comes from [`Self::fee_bounds`] (never from a
    /// block median), and the gas bounds are checked against the caller's
    /// ceiling. The returned [`Tx`] tracks the locally computed hash, so a
    /// lying endpoint cannot point the caller at a different transaction.
    pub async fn execute(&self, calls: Vec<Call>) -> Result<Tx> {
        use starknet_rust::accounts::{Account, ConnectedAccount};

        let nonce = self
            .account
            .get_nonce()
            .await
            .map_err(|e| KmsError::RpcError(e.to_string()))?;

        let bounds = match self.fee_bounds.explicit() {
            // Caller supplied every bound: no estimate, no endpoint input.
            Some(resolved) => resolved?,
            None => {
                let estimate = self
                    .account
                    .execute_v3(calls.clone())
                    .nonce(nonce)
                    .estimate_fee()
                    .await
                    .map_err(|e| KmsError::FeeEstimationFailed(e.to_string()))?;
                self.fee_bounds.resolve(&estimate_input(&estimate))?
            }
        };

        let prepared = apply_bounds(self.account.execute_v3(calls).nonce(nonce), &bounds)
            .prepared()
            .map_err(|e| KmsError::TransactionError(e.to_string()))?;

        let local_hash = prepared.transaction_hash(false);

        prepared
            .send()
            .await
            .map_err(|e| KmsError::TransactionError(e.to_string()))?;

        // The reported hash is never used: a substituted one could resolve to
        // another transaction's receipt and be read as this one succeeding.
        Ok(Tx::new(
            local_hash,
            self.provider.clone(),
            self.network.clone(),
        ))
    }

    /// Estimate fees for a list of calls.
    pub async fn estimate_fee(
        &self,
        calls: Vec<Call>,
    ) -> Result<starknet_rust::core::types::FeeEstimate> {
        use starknet_rust::accounts::Account;
        let estimate = self
            .account
            .execute_v3(calls)
            .estimate_fee()
            .await
            .map_err(|e| KmsError::FeeEstimationFailed(e.to_string()))?;

        Ok(estimate)
    }

    /// The wallet's address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The chain ID this wallet targets.
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// The network preset.
    pub fn network(&self) -> &NetworkPreset {
        &self.network
    }

    /// Start building a batched transaction.
    pub fn tx(&self) -> crate::tx::TxBuilder<'_> {
        crate::tx::TxBuilder::new(self)
    }
}

/// Convert a provider fee estimate into the Starknet-free shape `FeeBounds` takes.
pub(crate) fn estimate_input(
    estimate: &starknet_rust::core::types::FeeEstimate,
) -> FeeEstimateInput {
    FeeEstimateInput {
        l1_gas_consumed: estimate.l1_gas_consumed,
        l1_gas_price: estimate.l1_gas_price,
        l2_gas_consumed: estimate.l2_gas_consumed,
        l2_gas_price: estimate.l2_gas_price,
        l1_data_gas_consumed: estimate.l1_data_gas_consumed,
        l1_data_gas_price: estimate.l1_data_gas_price,
    }
}

/// Pin every fee field on an execution builder so none is filled from RPC.
fn apply_bounds<'a, A>(
    execution: starknet_rust::accounts::ExecutionV3<'a, A>,
    bounds: &ResolvedFeeBounds,
) -> starknet_rust::accounts::ExecutionV3<'a, A> {
    execution
        .l1_gas(bounds.l1_gas)
        .l1_gas_price(bounds.l1_gas_price)
        .l2_gas(bounds.l2_gas)
        .l2_gas_price(bounds.l2_gas_price)
        .l1_data_gas(bounds.l1_data_gas)
        .l1_data_gas_price(bounds.l1_data_gas_price)
        .tip(bounds.tip)
}

#[async_trait::async_trait]
impl WalletExecutor for Wallet {
    async fn execute(&self, calls: Vec<Call>) -> Result<Tx> {
        Wallet::execute(self, calls).await
    }

    async fn estimate_fee(
        &self,
        calls: Vec<Call>,
    ) -> Result<starknet_rust::core::types::FeeEstimate> {
        Wallet::estimate_fee(self, calls).await
    }

    fn address(&self) -> &Address {
        Wallet::address(self)
    }

    fn chain_id(&self) -> ChainId {
        Wallet::chain_id(self)
    }

    fn network(&self) -> &NetworkPreset {
        Wallet::network(self)
    }

    async fn is_deployed(&self) -> Result<bool> {
        Wallet::is_deployed(self).await
    }
}
