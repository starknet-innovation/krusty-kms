//! Cartridge Controller wallet integration.
//!
//! Provides [`ControllerWallet`] — a [`WalletExecutor`] backed by the
//! `account_sdk` crate, offering session-based signing, paymaster-sponsored
//! gas, and Cartridge identity.

pub mod convert;
pub mod error;
pub mod policy;

use std::sync::Arc;

use account_sdk::controller::Controller;
use account_sdk::execute_from_outside::FeeSource;
use account_sdk::signers::{Owner, Signer};
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::network::NetworkPreset;
use krusty_kms_common::{KmsError, Result};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use tokio::sync::Mutex;

pub use policy::{FeeMode, SessionPolicy};

use super::utils::check_deployed;
use super::WalletExecutor;
use crate::tx::Tx;

/// A Cartridge Controller wallet implementing [`WalletExecutor`].
///
/// Wraps `account_sdk::controller::Controller` with a `Mutex` because
/// `Controller::execute` requires `&mut self` while our trait uses `&self`.
pub struct ControllerWallet {
    controller: Mutex<Controller>,
    /// Our `starknet-rust 0.18` provider, used to construct [`Tx`] trackers.
    provider: Arc<JsonRpcClient<HttpTransport>>,
    address: Address,
    chain_id: ChainId,
    network: NetworkPreset,
    fee_mode: FeeMode,
    username: String,
}

impl ControllerWallet {
    /// Create from a Starknet signing key (headless / CLI mode).
    ///
    /// `address` must be the pre-computed controller account address.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        rpc_url: &str,
        username: String,
        chain_id: ChainId,
        network: NetworkPreset,
        private_key: starknet_types_core::felt::Felt,
        address: Address,
        class_hash: starknet_types_core::felt::Felt,
        fee_mode: FeeMode,
    ) -> Result<Self> {
        let url: url::Url = rpc_url
            .parse()
            .map_err(|e: url::ParseError| KmsError::RpcError(e.to_string()))?;

        let sdk_private_key = convert::felt_ours_to_sdk(private_key);
        let signing_key = starknet::signers::SigningKey::from_secret_scalar(sdk_private_key);
        let owner = Owner::Signer(Signer::Starknet(signing_key));

        let sdk_address = convert::felt_ours_to_sdk(address.as_felt());
        let sdk_class_hash = convert::felt_ours_to_sdk(class_hash);

        let controller = Controller::new(
            username.clone(),
            sdk_class_hash,
            url.clone(),
            owner,
            sdk_address,
            None,
        )
        .await
        .map_err(error::controller_error_to_kms)?;

        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(url)));

        Ok(Self {
            controller: Mutex::new(controller),
            provider,
            address,
            chain_id,
            network,
            fee_mode,
            username,
        })
    }

    /// Create from an existing `Controller` instance.
    pub fn from_controller(
        controller: Controller,
        provider: Arc<JsonRpcClient<HttpTransport>>,
        chain_id: ChainId,
        network: NetworkPreset,
        fee_mode: FeeMode,
    ) -> Self {
        let address = Address::from(convert::felt_sdk_to_ours(controller.address));
        let username = controller.username.clone();
        Self {
            controller: Mutex::new(controller),
            provider,
            address,
            chain_id,
            network,
            fee_mode,
            username,
        }
    }

    /// Create a session for the given policies.
    pub async fn create_session(
        &self,
        policies: Vec<SessionPolicy>,
        expires_secs: u64,
    ) -> Result<()> {
        let sdk_policies: Vec<_> = policies.iter().map(|p| p.to_sdk_policy()).collect();
        let mut ctrl = self.controller.lock().await;
        ctrl.create_session(sdk_policies, expires_secs)
            .await
            .map_err(error::controller_error_to_kms)?;
        Ok(())
    }

    /// Create a wildcard session (authorizes any call).
    pub async fn create_wildcard_session(&self, expires_secs: u64) -> Result<()> {
        let mut ctrl = self.controller.lock().await;
        ctrl.create_wildcard_session(expires_secs)
            .await
            .map_err(error::controller_error_to_kms)?;
        Ok(())
    }

    /// Deploy the controller account on-chain.
    pub async fn deploy(&self) -> Result<Tx> {
        let ctrl = self.controller.lock().await;
        let result = ctrl
            .deploy()
            .send()
            .await
            .map_err(|e| KmsError::TransactionError(e.to_string()))?;

        let hash = convert::felt_sdk_to_ours(result.transaction_hash);
        Ok(Tx::new(hash, self.provider.clone(), self.network.clone()))
    }

    /// Disconnect and clean up session state.
    pub fn disconnect(&self) -> Result<()> {
        let mut ctrl = self.controller.blocking_lock();
        ctrl.disconnect().map_err(error::controller_error_to_kms)
    }

    /// The Cartridge username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Set the fee mode.
    pub fn set_fee_mode(&mut self, mode: FeeMode) {
        self.fee_mode = mode;
    }

    /// The current fee mode.
    pub fn fee_mode(&self) -> &FeeMode {
        &self.fee_mode
    }

    /// Start building a batched transaction.
    pub fn tx(&self) -> crate::tx::TxBuilder<'_> {
        crate::tx::TxBuilder::new(self)
    }

    /// Access the raw Controller for advanced usage.
    pub async fn controller(&self) -> tokio::sync::MutexGuard<'_, Controller> {
        self.controller.lock().await
    }

    /// The underlying JSON-RPC provider.
    pub fn provider(&self) -> &Arc<JsonRpcClient<HttpTransport>> {
        &self.provider
    }

    /// Switch the controller to a different chain.
    pub async fn switch_chain(&self, rpc_url: &str) -> Result<()> {
        let url: url::Url = rpc_url
            .parse()
            .map_err(|e: url::ParseError| KmsError::RpcError(e.to_string()))?;
        let mut ctrl = self.controller.lock().await;
        ctrl.switch_chain(url).await.map_err(error::controller_error_to_kms)
    }
}

#[async_trait::async_trait]
impl WalletExecutor for ControllerWallet {
    async fn execute(&self, calls: Vec<starknet_rust::core::types::Call>) -> Result<Tx> {
        let sdk_calls: Vec<_> = calls.iter().map(convert::call_to_sdk).collect();
        let mut ctrl = self.controller.lock().await;

        let result = match self.fee_mode {
            FeeMode::UserPays => {
                let fee = ctrl
                    .estimate_invoke_fee(sdk_calls.clone())
                    .await
                    .map_err(error::controller_error_to_kms)?;
                ctrl.execute(sdk_calls, Some(fee), None)
                    .await
                    .map_err(error::controller_error_to_kms)?
            }
            FeeMode::Sponsored => ctrl
                .execute(sdk_calls, None, Some(FeeSource::Paymaster))
                .await
                .map_err(error::controller_error_to_kms)?,
            FeeMode::Credits => ctrl
                .execute(sdk_calls, None, Some(FeeSource::Credits))
                .await
                .map_err(error::controller_error_to_kms)?,
        };

        let hash = convert::felt_sdk_to_ours(result.transaction_hash);
        Ok(Tx::new(hash, self.provider.clone(), self.network.clone()))
    }

    async fn estimate_fee(
        &self,
        calls: Vec<starknet_rust::core::types::Call>,
    ) -> Result<starknet_rust::core::types::FeeEstimate> {
        let sdk_calls: Vec<_> = calls.iter().map(convert::call_to_sdk).collect();
        let ctrl = self.controller.lock().await;
        let est = ctrl
            .estimate_invoke_fee(sdk_calls)
            .await
            .map_err(error::controller_error_to_kms)?;
        Ok(convert::fee_estimate_to_ours(&est))
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
        let address_rs = super::utils::core_felt_to_rs(self.address.as_felt());
        check_deployed(&self.provider, address_rs).await
    }
}
