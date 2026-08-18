//! Default Starknet JSON-RPC implementation of [`GatewayBackend`].

use super::deploy::{map_deploy_submission_error, validate_open_zeppelin_descriptor};
use super::interface::{DeployExecution, GatewayBackend};
use super::rpc::{
    balance_of_camel_selector, balance_of_selector, call_erc20_balance_with_selector_fallback,
    core_felt_to_rs, is_contract_not_found, provider_transport_error, rs_felt_to_biguint,
    rs_felt_to_core, to_block_id,
};
use super::wait::wait_for_acceptance;
use crate::{map_kms_error, GatewayResult};
use async_trait::async_trait;
use krusty_kms_common::fee::{FeeBounds, FeeEstimateInput, ResolvedFeeBounds};
use krusty_kms_common::{ChainId, KmsError, NetworkPreset, SecretFelt};
use krusty_kms_domain::{
    AccountDescriptor, BlockSelector, DeployMode, FeltHex, GatewayError, GatewayErrorCode,
    SnapshotBlockMetadata, TrackedToken,
};
use num_bigint::BigUint;
use starknet_rust::accounts::{AccountFactory, OpenZeppelinAccountFactory};
use starknet_rust::core::types::{FunctionCall, MaybePreConfirmedBlockWithTxHashes};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;
use starknet_rust::signers::{LocalWallet, SigningKey};
use std::sync::Arc;

/// Default Starknet JSON-RPC backend backed directly by Starknet JSON-RPC primitives.
pub struct StarknetGatewayBackend {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    network: NetworkPreset,
    fee_bounds: FeeBounds,
}

impl StarknetGatewayBackend {
    pub fn new(provider: Arc<JsonRpcClient<HttpTransport>>, network: NetworkPreset) -> Self {
        Self {
            provider,
            network,
            fee_bounds: FeeBounds::default(),
        }
    }

    /// Replace the fee bounds every deployment is signed within.
    ///
    /// Defaults to [`FeeBounds::default`], which pins the tip to zero and caps
    /// the total at [`krusty_kms_common::fee::DEFAULT_MAX_FEE_FRI`].
    #[must_use]
    pub fn with_fee_bounds(mut self, fee_bounds: FeeBounds) -> Self {
        self.fee_bounds = fee_bounds;
        self
    }

    /// The fee bounds applied to every deployment this backend submits.
    pub fn fee_bounds(&self) -> &FeeBounds {
        &self.fee_bounds
    }

    pub fn provider(&self) -> &Arc<JsonRpcClient<HttpTransport>> {
        &self.provider
    }

    pub fn network(&self) -> &NetworkPreset {
        &self.network
    }
}

#[async_trait]
impl GatewayBackend for StarknetGatewayBackend {
    fn chain_id(&self) -> ChainId {
        self.network.chain_id
    }

    async fn check_deployed(
        &self,
        address: &FeltHex,
        block: &BlockSelector,
    ) -> GatewayResult<bool> {
        let address_rs = core_felt_to_rs(address.to_felt());
        match self
            .provider
            .get_class_hash_at(to_block_id(block), address_rs)
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_contract_not_found(&error) => Ok(false),
            Err(error) => Err(provider_transport_error(error.to_string())),
        }
    }

    // NOTE: intentionally over the 40-line guideline, for the same reason as
    // the client's deploy path: chain guard -> descriptor validation ->
    // deployed-check -> nonce -> bounds -> submit -> wait is a sequence whose
    // order is the point. It was already over before fee bounds were added.
    async fn deploy_open_zeppelin(
        &self,
        private_key: &SecretFelt,
        account: &AccountDescriptor,
        mode: DeployMode,
    ) -> GatewayResult<DeployExecution> {
        let chain_id = account.provenance.chain_id;
        if chain_id != self.network.chain_id {
            return Err(GatewayError::new(
                GatewayErrorCode::ChainMismatch,
                false,
                Some(format!(
                    "account descriptor targets {}, backend is configured for {}",
                    chain_id, self.network.chain_id
                )),
            ));
        }

        let signing_key =
            SigningKey::from_secret_scalar(core_felt_to_rs(*private_key.expose_secret()));
        validate_open_zeppelin_descriptor(account, &signing_key)?;

        if self
            .check_deployed(&account.address, &BlockSelector::Latest)
            .await?
        {
            return Ok(DeployExecution::AlreadyDeployed);
        }

        let signer = LocalWallet::from(signing_key);
        let factory = OpenZeppelinAccountFactory::new(
            core_felt_to_rs(account.class_hash.to_felt()),
            core_felt_to_rs(chain_id.as_felt()),
            signer,
            self.provider.clone(),
        )
        .await
        .map_err(|error| map_kms_error(KmsError::CryptoError(error.to_string())))?;

        let salt = core_felt_to_rs(account.salt.to_felt());

        // Not pinned to zero: a reverted deploy still lands in a block and bumps
        // the nonce of an account that is still undeployed. Untrusted input is
        // fine here — a wrong nonce only makes the transaction unincludeable.
        let nonce = factory
            .deploy_v3(salt)
            .fetch_nonce()
            .await
            .map_err(|error| provider_transport_error(error.to_string()))?;

        let bounds = resolve_bounds(&factory, salt, nonce, &self.fee_bounds).await?;

        let prepared = apply_bounds(factory.deploy_v3(salt).nonce(nonce), &bounds)
            .prepared()
            .map_err(|error| map_kms_error(KmsError::TransactionError(error.to_string())))?;

        let local_hash = prepared.transaction_hash(false);

        prepared.send().await.map_err(map_deploy_submission_error)?;

        // The reported hash is never used: a substituted one could resolve to
        // another transaction's receipt and be read as this one succeeding.
        let tx_hash = FeltHex::from_felt(rs_felt_to_core(local_hash));
        match mode {
            DeployMode::SubmitOnly => Ok(DeployExecution::Submitted { tx_hash }),
            DeployMode::WaitForAcceptance(wait) => {
                wait_for_acceptance(
                    &self.provider,
                    local_hash,
                    wait.poll_interval_ms,
                    wait.timeout_ms,
                )
                .await
                .map_err(map_kms_error)?;
                Ok(DeployExecution::Accepted { tx_hash })
            }
        }
    }

    async fn nonce(&self, address: &FeltHex, block: &BlockSelector) -> GatewayResult<FeltHex> {
        let nonce = self
            .provider
            .get_nonce(to_block_id(block), core_felt_to_rs(address.to_felt()))
            .await
            .map_err(|error| provider_transport_error(error.to_string()))?;
        Ok(FeltHex::from_felt(rs_felt_to_core(nonce)))
    }

    async fn token_balance(
        &self,
        address: &FeltHex,
        token: &TrackedToken,
        block: &BlockSelector,
    ) -> GatewayResult<String> {
        let token_address = core_felt_to_rs(token.address.to_felt());
        let account_address = core_felt_to_rs(address.to_felt());
        let block_id = to_block_id(block);
        let function = FunctionCall {
            contract_address: token_address,
            entry_point_selector: balance_of_selector(),
            calldata: vec![account_address],
        };
        let result = call_erc20_balance_with_selector_fallback(
            &self.provider,
            function,
            block_id,
            FunctionCall {
                contract_address: token_address,
                entry_point_selector: balance_of_camel_selector(),
                calldata: vec![account_address],
            },
        )
        .await?;

        if result.is_empty() {
            return Err(GatewayError::new(
                GatewayErrorCode::ProviderTransport,
                true,
                Some(format!("empty balance response for token {}", token.symbol)),
            ));
        }

        let low = rs_felt_to_biguint(&result[0]);
        let high = if result.len() > 1 {
            rs_felt_to_biguint(&result[1])
        } else {
            BigUint::default()
        };

        Ok(((high << 128usize) + low).to_string())
    }

    async fn block_metadata(&self, block: &BlockSelector) -> GatewayResult<SnapshotBlockMetadata> {
        if matches!(block, BlockSelector::Latest) {
            let block_ref = self
                .provider
                .block_hash_and_number()
                .await
                .map_err(|error| provider_transport_error(error.to_string()))?;
            return Ok(SnapshotBlockMetadata {
                selector: block.clone(),
                block_hash: Some(FeltHex::from_felt(rs_felt_to_core(block_ref.block_hash))),
                block_number: Some(block_ref.block_number),
            });
        }

        let block_info = self
            .provider
            .get_block_with_tx_hashes(to_block_id(block))
            .await
            .map_err(|error| provider_transport_error(error.to_string()))?;

        let (block_hash, block_number) = match block_info {
            MaybePreConfirmedBlockWithTxHashes::Block(block) => (
                Some(FeltHex::from_felt(rs_felt_to_core(block.block_hash))),
                Some(block.block_number),
            ),
            MaybePreConfirmedBlockWithTxHashes::PreConfirmedBlock(block) => {
                (None, Some(block.block_number))
            }
        };

        Ok(SnapshotBlockMetadata {
            selector: block.clone(),
            block_hash,
            block_number,
        })
    }
}

/// A ceiling refusal is the caller's own policy, so it is not retryable.
///
/// Not routed through `map_kms_error`, which classifies by substring and would
/// land this in the retryable `RpcDegraded`.
fn fee_bounds_rejected(error: KmsError) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::InvalidRequest,
        false,
        Some(error.to_string()),
    )
}

/// Convert a provider fee estimate into the Starknet-free shape `FeeBounds` takes.
fn estimate_input(estimate: &starknet_rust::core::types::FeeEstimate) -> FeeEstimateInput {
    FeeEstimateInput {
        l1_gas_consumed: estimate.l1_gas_consumed,
        l1_gas_price: estimate.l1_gas_price,
        l2_gas_consumed: estimate.l2_gas_consumed,
        l2_gas_price: estimate.l2_gas_price,
        l1_data_gas_consumed: estimate.l1_data_gas_consumed,
        l1_data_gas_price: estimate.l1_data_gas_price,
    }
}

/// Pin every fee field on a deploy builder so none is filled from RPC.
fn apply_bounds<'a, F>(
    deployment: starknet_rust::accounts::AccountDeploymentV3<'a, F>,
    bounds: &ResolvedFeeBounds,
) -> starknet_rust::accounts::AccountDeploymentV3<'a, F> {
    deployment
        .l1_gas(bounds.l1_gas)
        .l1_gas_price(bounds.l1_gas_price)
        .l2_gas(bounds.l2_gas)
        .l2_gas_price(bounds.l2_gas_price)
        .l1_data_gas(bounds.l1_data_gas)
        .l1_data_gas_price(bounds.l1_data_gas_price)
        .tip(bounds.tip)
}

/// Bounds for this deployment, estimating only when the caller left a gap.
async fn resolve_bounds(
    factory: &OpenZeppelinAccountFactory<LocalWallet, Arc<JsonRpcClient<HttpTransport>>>,
    salt: starknet_rust::core::types::Felt,
    nonce: starknet_rust::core::types::Felt,
    fee_bounds: &FeeBounds,
) -> GatewayResult<ResolvedFeeBounds> {
    // Caller supplied every bound: no estimate, no endpoint input.
    if let Some(resolved) = fee_bounds.explicit() {
        return resolved.map_err(fee_bounds_rejected);
    }

    let estimate = factory
        .deploy_v3(salt)
        .nonce(nonce)
        .estimate_fee()
        .await
        .map_err(map_deploy_submission_error)?;

    fee_bounds
        .resolve(&estimate_input(&estimate))
        .map_err(fee_bounds_rejected)
}
