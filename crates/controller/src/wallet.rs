//! Cartridge Controller wallet.

use std::sync::Arc;

use account_sdk::controller::Controller;
use account_sdk::execute_from_outside::FeeSource;
use account_sdk::signers::{Owner, Signer};
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::network::NetworkPreset;
use krusty_kms_common::{KmsError, Result};
use krusty_kms_wallet_api::{Tx, WalletExecutor};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::{Provider, ProviderError};
use tokio::sync::Mutex;

use crate::convert;
use crate::error;
use crate::policy::FeeMode;
use crate::tx_builder::TxBuilder;
use crate::SessionPolicy;

/// A Cartridge Controller wallet implementing the shared wallet execution boundary.
///
/// Wraps `account_sdk::controller::Controller` with a `Mutex` because
/// `Controller::execute` requires `&mut self` while our trait uses `&self`.
pub struct ControllerWallet {
    controller: Mutex<Controller>,
    /// Our `starknet-rust 0.18` provider, used to construct [`Tx`] trackers.
    provider: Arc<JsonRpcClient<HttpTransport>>,
    address: Address,
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
        validate_network_chain(chain_id, &network)?;

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
    ) -> Result<Self> {
        validate_network_chain(chain_id, &network)?;
        let address = Address::from(convert::felt_sdk_to_ours(controller.address));
        let username = controller.username.clone();
        Ok(Self {
            controller: Mutex::new(controller),
            provider,
            address,
            network,
            fee_mode,
            username,
        })
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

    /// Create a dangerous wildcard session that authorizes any call.
    ///
    /// # Safety / danger
    /// This grants unrestricted session authority. Prefer
    /// [`Self::create_session`] with explicit [`SessionPolicy`] allowlists.
    ///
    /// The old name `create_wildcard_session` is kept as a deprecated alias.
    pub async fn create_dangerous_wildcard_session(&self, expires_secs: u64) -> Result<()> {
        let mut ctrl = self.controller.lock().await;
        ctrl.create_wildcard_session(expires_secs)
            .await
            .map_err(error::controller_error_to_kms)?;
        Ok(())
    }

    /// Deprecated alias for [`Self::create_dangerous_wildcard_session`].
    #[deprecated(
        note = "use create_dangerous_wildcard_session; wildcard sessions authorize any call"
    )]
    pub async fn create_wildcard_session(&self, expires_secs: u64) -> Result<()> {
        self.create_dangerous_wildcard_session(expires_secs).await
    }

    /// Controller deployment is disabled until the pinned SDK exposes a
    /// caller-approved fee and local-hash boundary.
    pub async fn deploy(&self) -> Result<Tx> {
        Err(unsupported_user_paid("deployment"))
    }

    /// Disconnect and clean up session state.
    pub async fn disconnect(&self) -> Result<()> {
        let mut ctrl = self.controller.lock().await;
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
    pub fn tx(&self) -> TxBuilder<'_> {
        TxBuilder::new(self)
    }

    /// The underlying JSON-RPC provider.
    pub fn provider(&self) -> &Arc<JsonRpcClient<HttpTransport>> {
        &self.provider
    }

    /// Switch the controller to a different chain.
    ///
    /// Updates the inner Controller's RPC target **and** the local provider,
    /// chain ID, and network preset so that subsequent `execute` / `deploy`
    /// calls (and the `Tx` trackers they return) point at the new chain.
    pub async fn switch_chain(
        &mut self,
        rpc_url: &str,
        chain_id: ChainId,
        network: NetworkPreset,
    ) -> Result<()> {
        validate_network_chain(chain_id, &network)?;

        let url: url::Url = rpc_url
            .parse()
            .map_err(|e: url::ParseError| KmsError::RpcError(e.to_string()))?;
        let mut ctrl = self.controller.lock().await;
        ctrl.switch_chain(url.clone())
            .await
            .map_err(error::controller_error_to_kms)?;
        drop(ctrl);

        self.provider = Arc::new(JsonRpcClient::new(HttpTransport::new(url)));
        self.network = network;
        Ok(())
    }
}

#[async_trait::async_trait]
impl WalletExecutor for ControllerWallet {
    async fn execute(&self, calls: Vec<starknet_rust::core::types::Call>) -> Result<Tx> {
        let sdk_calls: Vec<_> = calls.iter().map(convert::call_to_sdk).collect();
        let fee_source = match self.fee_mode {
            FeeMode::UserPays => return Err(unsupported_user_paid("execution")),
            FeeMode::Sponsored => FeeSource::Paymaster,
            FeeMode::Credits => FeeSource::Credits,
        };
        let mut ctrl = self.controller.lock().await;
        let result = ctrl
            .execute(sdk_calls, None, Some(fee_source))
            .await
            .map_err(error::controller_error_to_kms)?;

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
        self.network.chain_id
    }

    fn network(&self) -> &NetworkPreset {
        &self.network
    }

    async fn is_deployed(&self) -> Result<bool> {
        let address_rs = convert::felt_core_to_ours(self.address.as_felt());
        check_deployed(&self.provider, address_rs).await
    }
}

fn unsupported_user_paid(operation: &str) -> KmsError {
    KmsError::ControllerError(format!(
        "controller {operation} is disabled: the pinned account_sdk cannot enforce \
         caller-approved fee bounds and a locally computed transaction hash; use sponsored or \
         credit execution for already-deployed accounts until that boundary is available"
    ))
}

async fn check_deployed(
    provider: &Arc<JsonRpcClient<HttpTransport>>,
    address: starknet_rust::core::types::Felt,
) -> Result<bool> {
    match provider
        .get_class_hash_at(
            starknet_rust::core::types::BlockId::Tag(starknet_rust::core::types::BlockTag::Latest),
            address,
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(ProviderError::StarknetError(
            starknet_rust::core::types::StarknetError::ContractNotFound,
        )) => Ok(false),
        Err(error) => Err(KmsError::RpcError(error.to_string())),
    }
}

fn validate_network_chain(chain_id: ChainId, network: &NetworkPreset) -> Result<()> {
    if chain_id == network.chain_id {
        return Ok(());
    }

    Err(KmsError::ControllerError(format!(
        "network {} is configured for {}, not {}",
        network.name, network.chain_id, chain_id
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_network_chain_rejects_mismatch() {
        let error =
            validate_network_chain(ChainId::Mainnet, &NetworkPreset::sepolia()).unwrap_err();
        assert!(matches!(error, KmsError::ControllerError(_)));
    }

    #[test]
    fn validate_network_chain_accepts_matching_network() {
        assert!(validate_network_chain(ChainId::Sepolia, &NetworkPreset::sepolia()).is_ok());
    }

    #[test]
    fn user_paid_guard_fails_closed_with_a_remediation() {
        let error = unsupported_user_paid("execution").to_string();
        assert!(error.contains("caller-approved fee bounds"), "got: {error}");
        assert!(error.contains("sponsored or credit"), "got: {error}");
    }
}
