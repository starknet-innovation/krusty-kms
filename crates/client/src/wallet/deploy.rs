//! Canonical OpenZeppelin account deployment.
//!
//! Provides a single, opinionated path from key derivation to on-chain
//! deployment so that integrators cannot accidentally diverge on salt,
//! class hash, or constructor calldata.

use krusty_kms::{OpenZeppelinAccount, SaltPolicy};
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::fee::{FeeBounds, ResolvedFeeBounds};
use krusty_kms_common::network::NetworkPreset;
use krusty_kms_common::{KmsError, Result};
use starknet_rust::accounts::AccountFactory;
use starknet_rust::accounts::OpenZeppelinAccountFactory;
use starknet_rust::core::types::FeeEstimate;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::signers::{LocalWallet, SigningKey};
use std::sync::Arc;

use super::utils::{check_deployed, core_felt_to_rs, map_deploy_factory_error};
use crate::tx::Tx;

/// Result of [`deploy_oz_account`].
pub struct DeployResult {
    /// The on-chain address of the account.
    pub address: Address,
    /// The deploy transaction tracker, or `None` if the account was already deployed.
    pub tx: Option<Tx>,
    /// `true` when the account was already on-chain before this call.
    pub already_deployed: bool,
}

/// Deploy an OpenZeppelin account contract using the canonical derivation path.
///
/// 1. Builds an [`krusty_kms::OzDeploymentDescriptor`] from `account_class` (same
///    canonical path used for address derivation).
/// 2. Resolves the deploy salt from `salt_policy`.
/// 3. Checks whether the account is already deployed on-chain.
/// 4. If not, submits a `DEPLOY_ACCOUNT` v3 transaction.
///
/// Provider errors are mapped to typed [`KmsError`] variants.
pub async fn deploy_oz_account(
    provider: Arc<JsonRpcClient<HttpTransport>>,
    signing_key: &SigningKey,
    account_class: &OpenZeppelinAccount,
    salt_policy: SaltPolicy,
    chain_id: ChainId,
    network: NetworkPreset,
) -> Result<DeployResult> {
    deploy_oz_account_with_bounds(
        provider,
        signing_key,
        account_class,
        salt_policy,
        chain_id,
        network,
        &FeeBounds::default(),
    )
    .await
}

/// Deploy an OpenZeppelin account within caller-supplied fee bounds.
///
/// Identical to [`deploy_oz_account`] but lets the caller cap what the
/// deployment may cost. The tip is pinned from `fee_bounds` rather than taken
/// from a block median, and the returned [`Tx`] tracks the locally computed
/// transaction hash; the one the endpoint reports is ignored.
// NOTE: intentionally over the 40-line guideline. This is the canonical
// derivation-to-deployment path, and splitting it further would scatter the
// order of descriptor -> deployed-check -> nonce -> bounds -> submit across
// helpers where the sequencing is the thing a reader needs to see. It was
// already over before fee bounds were threaded through.
pub async fn deploy_oz_account_with_bounds(
    provider: Arc<JsonRpcClient<HttpTransport>>,
    signing_key: &SigningKey,
    account_class: &OpenZeppelinAccount,
    salt_policy: SaltPolicy,
    chain_id: ChainId,
    network: NetworkPreset,
    fee_bounds: &FeeBounds,
) -> Result<DeployResult> {
    let verifying_key = signing_key.verifying_key();
    let public_key_rs = verifying_key.scalar();
    let public_key_core = super::utils::rs_felt_to_core(public_key_rs);

    let descriptor = account_class.deployment_descriptor(&public_key_core, salt_policy)?;
    let address = Address::from(descriptor.address);
    let address_rs = core_felt_to_rs(descriptor.address);

    // Check current deployment status.
    let deployed = check_deployed(&provider, address_rs).await?;
    if deployed {
        return Ok(DeployResult {
            address,
            tx: None,
            already_deployed: true,
        });
    }

    // Build the factory and submit the deploy transaction.
    let class_hash_rs = core_felt_to_rs(descriptor.class_hash);
    let chain_id_rs = core_felt_to_rs(chain_id.as_felt());
    let salt_rs = core_felt_to_rs(descriptor.salt);

    let signer = LocalWallet::from(signing_key.clone());
    let factory =
        OpenZeppelinAccountFactory::new(class_hash_rs, chain_id_rs, signer, provider.clone())
            .await
            .map_err(|e| KmsError::CryptoError(e.to_string()))?;

    // Not pinned to zero: a reverted deploy still lands in a block and bumps
    // the nonce of an account that is still undeployed. Untrusted input is
    // fine here — a wrong nonce only makes the transaction unincludeable.
    let nonce = factory
        .deploy_v3(salt_rs)
        .fetch_nonce()
        .await
        .map_err(|e| KmsError::RpcError(e.to_string()))?;

    let bounds = resolve_bounds(&factory, salt_rs, nonce, fee_bounds).await?;

    let prepared = apply_bounds(factory.deploy_v3(salt_rs).nonce(nonce), &bounds)
        .prepared()
        .map_err(|e| KmsError::TransactionError(e.to_string()))?;

    let local_hash = prepared.transaction_hash(false);

    prepared.send().await.map_err(map_deploy_factory_error)?;

    // The reported hash is never used: a substituted one could resolve to
    // another transaction's receipt and be read as this one succeeding.
    let tx = Tx::new(local_hash, provider, network);

    Ok(DeployResult {
        address,
        tx: Some(tx),
        already_deployed: false,
    })
}

/// Estimate the fee for deploying an OpenZeppelin account (without submitting).
pub async fn estimate_deploy_fee(
    provider: Arc<JsonRpcClient<HttpTransport>>,
    signing_key: &SigningKey,
    account_class: &OpenZeppelinAccount,
    salt_policy: SaltPolicy,
    chain_id: ChainId,
) -> Result<FeeEstimate> {
    let verifying_key = signing_key.verifying_key();
    let public_key_rs = verifying_key.scalar();
    let public_key_core = super::utils::rs_felt_to_core(public_key_rs);

    let descriptor = account_class.deployment_descriptor(&public_key_core, salt_policy)?;

    let class_hash_rs = core_felt_to_rs(descriptor.class_hash);
    let chain_id_rs = core_felt_to_rs(chain_id.as_felt());
    let salt_rs = core_felt_to_rs(descriptor.salt);

    let signer = LocalWallet::from(signing_key.clone());
    let factory =
        OpenZeppelinAccountFactory::new(class_hash_rs, chain_id_rs, signer, provider.clone())
            .await
            .map_err(|e| KmsError::CryptoError(e.to_string()))?;

    factory
        .deploy_v3(salt_rs)
        .estimate_fee()
        .await
        .map_err(map_deploy_factory_error)
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
) -> Result<ResolvedFeeBounds> {
    // Caller supplied every bound: no estimate, no endpoint input.
    if let Some(resolved) = fee_bounds.explicit() {
        return resolved;
    }

    let estimate = factory
        .deploy_v3(salt)
        .nonce(nonce)
        .estimate_fee()
        .await
        .map_err(map_deploy_factory_error)?;

    fee_bounds.resolve(&super::estimate_input(&estimate))
}
