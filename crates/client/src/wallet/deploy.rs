//! Canonical OpenZeppelin account deployment.
//!
//! Provides a single, opinionated path from key derivation to on-chain
//! deployment so that integrators cannot accidentally diverge on salt,
//! class hash, or constructor calldata.

use krusty_kms::{OpenZeppelinAccount, SaltPolicy};
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
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
/// 1. Builds an [`OzDeploymentDescriptor`] from `account_class` (same canonical path
///    used for address derivation).
/// 2. Resolves the deploy salt from `salt_policy`.
/// 3. Checks if the account is already deployed via [`check_deployed`].
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

    let result = factory
        .deploy_v3(salt_rs)
        .send()
        .await
        .map_err(map_deploy_factory_error)?;

    let tx = Tx::new(result.transaction_hash, provider, network);

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
