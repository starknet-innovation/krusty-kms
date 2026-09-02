//! Default Starknet JSON-RPC implementation of [`GatewayBackend`].

use super::deploy::{map_deploy_submission_error, validate_open_zeppelin_descriptor};
use super::interface::{DeployExecution, GatewayBackend};
use super::rpc::{
    balance_of_camel_selector, balance_of_selector, call_erc20_balance_with_selector_fallback,
    core_felt_to_rs, is_contract_not_found, map_provider_error, rs_felt_to_biguint,
    rs_felt_to_core, to_block_id,
};
use super::wait::wait_for_acceptance;
use super::StarknetRsFelt;
use crate::{map_kms_error, GatewayResult};
use async_trait::async_trait;
use krusty_kms::stark_public_key;
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
}

impl StarknetGatewayBackend {
    pub fn new(provider: Arc<JsonRpcClient<HttpTransport>>, network: NetworkPreset) -> Self {
        Self { provider, network }
    }

    pub fn provider(&self) -> &Arc<JsonRpcClient<HttpTransport>> {
        &self.provider
    }

    pub fn network(&self) -> &NetworkPreset {
        &self.network
    }

    /// Submit the `DEPLOY_ACCOUNT` transaction and return only its hash.
    ///
    /// Invariant: starknet-rs `SigningKey` copies the secret scalar into a
    /// plain `Felt` that is neither zeroized on drop nor redacted in `Debug`.
    /// The key, the `LocalWallet`, and the account factory built on it must
    /// not outlive this function, so every copy is dropped before the caller
    /// starts an acceptance wait (which may run for minutes).
    async fn submit_open_zeppelin_deploy(
        &self,
        private_key: &SecretFelt,
        account: &AccountDescriptor,
    ) -> GatewayResult<StarknetRsFelt> {
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(core_felt_to_rs(
            *private_key.expose_secret(),
        )));
        let factory = OpenZeppelinAccountFactory::new(
            core_felt_to_rs(account.class_hash.to_felt()),
            core_felt_to_rs(account.provenance.chain_id.as_felt()),
            signer,
            self.provider.clone(),
        )
        .await
        .map_err(|error| map_kms_error(KmsError::CryptoError(error.to_string())))?;

        let submission = factory
            .deploy_v3(core_felt_to_rs(account.salt.to_felt()))
            .send()
            .await
            .map_err(map_deploy_submission_error)?;
        Ok(submission.transaction_hash)
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
            Err(error) => Err(map_provider_error(error)),
        }
    }

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

        // Descriptor validation stays on the kms-native path so the secret is
        // read in place rather than copied into a starknet-rs `SigningKey`.
        let derived_public_key =
            stark_public_key(private_key.expose_secret()).map_err(map_kms_error)?;
        validate_open_zeppelin_descriptor(account, derived_public_key)?;

        if self
            .check_deployed(&account.address, &BlockSelector::Latest)
            .await?
        {
            return Ok(DeployExecution::AlreadyDeployed);
        }

        // The signer lives only inside `submit_open_zeppelin_deploy`; by the
        // time we wait for acceptance no starknet-rs copy of the key remains.
        let submitted_hash = self
            .submit_open_zeppelin_deploy(private_key, account)
            .await?;

        let tx_hash = FeltHex::from_felt(rs_felt_to_core(submitted_hash));
        match mode {
            DeployMode::SubmitOnly => Ok(DeployExecution::Submitted { tx_hash }),
            DeployMode::WaitForAcceptance(wait) => {
                wait_for_acceptance(
                    &self.provider,
                    submitted_hash,
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
            .map_err(map_provider_error)?;
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
                .map_err(map_provider_error)?;
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
            .map_err(map_provider_error)?;

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
