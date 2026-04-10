//! Wallet: owns a provider + account, can sign and execute transactions.

pub mod deploy;
pub mod utils;

use krusty_kms::{AccountClass, SaltPolicy};
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
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
            deployed_cache: RwLock::new(None),
        })
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

    /// Execute a list of calls via `execute_v3`.
    pub async fn execute(&self, calls: Vec<Call>) -> Result<Tx> {
        use starknet_rust::accounts::Account;
        let result = self
            .account
            .execute_v3(calls)
            .send()
            .await
            .map_err(|e| KmsError::TransactionError(e.to_string()))?;

        Ok(Tx::new(
            result.transaction_hash,
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
