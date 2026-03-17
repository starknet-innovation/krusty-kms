use crate::{map_kms_error, GatewayResult};
use async_trait::async_trait;
use krusty_kms::{OpenZeppelinAccount, SaltPolicy};
use krusty_kms_client::{abi, deploy_oz_account, tx::Tx};
use krusty_kms_common::{ChainId, KmsError, NetworkPreset, SecretFelt};
use krusty_kms_domain::{
    AccountDescriptor, BlockSelector, DeployMode, FeltHex, GatewayError, GatewayErrorCode,
    SnapshotBlockMetadata, TrackedToken,
};
use num_bigint::BigUint;
use starknet_rust::core::types::{
    BlockId, BlockTag, FunctionCall, MaybePreConfirmedBlockWithTxHashes,
};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;
use starknet_rust::signers::SigningKey;
use starknet_types_core::felt::Felt as CoreFelt;
use std::sync::Arc;
use std::time::{Duration, Instant};

type StarknetRsFelt = starknet_rust::core::types::Felt;

/// Runtime execution result for a deploy-account operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployExecution {
    AlreadyDeployed,
    Submitted { tx_hash: FeltHex },
    Accepted { tx_hash: FeltHex },
}

/// Replaceable effectful boundary used by the gateway runtime.
#[async_trait]
pub trait GatewayBackend: Send + Sync {
    /// Chain this backend is configured for.
    fn chain_id(&self) -> ChainId;

    /// Check whether `address` is deployed at the selected block.
    async fn check_deployed(&self, address: &FeltHex, block: &BlockSelector)
        -> GatewayResult<bool>;

    /// Submit an OpenZeppelin account deployment, optionally waiting for receipt availability.
    async fn deploy_open_zeppelin(
        &self,
        private_key: &SecretFelt,
        account: &AccountDescriptor,
        mode: DeployMode,
    ) -> GatewayResult<DeployExecution>;

    /// Query the Starknet nonce for a deployed account.
    async fn nonce(&self, address: &FeltHex, block: &BlockSelector) -> GatewayResult<FeltHex>;

    /// Query the raw ERC-20 balance for one token.
    async fn token_balance(
        &self,
        address: &FeltHex,
        token: &TrackedToken,
        block: &BlockSelector,
    ) -> GatewayResult<String>;

    /// Resolve block metadata matching a selector.
    async fn block_metadata(&self, block: &BlockSelector) -> GatewayResult<SnapshotBlockMetadata>;
}

/// Default Starknet JSON-RPC backend that delegates to the existing client crate.
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
            Err(error) => {
                let message = error.to_string();
                if is_contract_not_found(&message) {
                    Ok(false)
                } else {
                    Err(provider_transport_error(message))
                }
            }
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

        let signing_key =
            SigningKey::from_secret_scalar(core_felt_to_rs(*private_key.expose_secret()));
        let account_class = OpenZeppelinAccount::from_class_hash(account.class_hash.to_felt());
        let result = deploy_oz_account(
            self.provider.clone(),
            &signing_key,
            &account_class,
            descriptor_salt_policy(account),
            chain_id,
            self.network.clone(),
        )
        .await
        .map_err(map_kms_error)?;

        if result.already_deployed {
            return Ok(DeployExecution::AlreadyDeployed);
        }

        let tx = result.tx.ok_or_else(|| {
            GatewayError::new(
                GatewayErrorCode::ProviderTransport,
                true,
                Some("deploy submission returned without a transaction handle".to_string()),
            )
        })?;

        let tx_hash = FeltHex::from_felt(rs_felt_to_core(tx.hash()));
        match mode {
            DeployMode::SubmitOnly => Ok(DeployExecution::Submitted { tx_hash }),
            DeployMode::WaitForAcceptance(wait) => {
                wait_for_receipt(&tx, wait.poll_interval_ms, wait.timeout_ms)
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
            entry_point_selector: *abi::erc20::BALANCE_OF,
            calldata: vec![account_address],
        };

        let result = match self.provider.call(function, block_id).await {
            Ok(result) => result,
            Err(_) => {
                let fallback = FunctionCall {
                    contract_address: token_address,
                    entry_point_selector: *abi::erc20::BALANCE_OF_CAMEL,
                    calldata: vec![account_address],
                };
                self.provider
                    .call(fallback, to_block_id(block))
                    .await
                    .map_err(|error| provider_transport_error(error.to_string()))?
            }
        };

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

async fn wait_for_receipt(tx: &Tx, poll_interval_ms: u64, timeout_ms: u64) -> Result<(), KmsError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let interval = Duration::from_millis(poll_interval_ms);

    loop {
        if Instant::now() >= deadline {
            return Err(KmsError::Timeout(format!(
                "transaction {} not accepted within {}ms",
                tx.hash_hex(),
                timeout_ms
            )));
        }

        match tx.receipt().await {
            Ok(_) => return Ok(()),
            Err(_) => tokio::time::sleep(interval).await,
        }
    }
}

fn descriptor_salt_policy(account: &AccountDescriptor) -> SaltPolicy {
    let salt = account.salt.to_felt();
    let public_key = account.public_key.to_felt();

    if salt == public_key {
        SaltPolicy::PublicKey
    } else if salt == CoreFelt::ZERO {
        SaltPolicy::Zero
    } else {
        SaltPolicy::Explicit(salt)
    }
}

fn provider_transport_error(message: String) -> GatewayError {
    GatewayError::new(GatewayErrorCode::ProviderTransport, true, Some(message))
}

fn is_contract_not_found(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("not found")
        || lower.contains("is not deployed")
        || lower.contains("contractnotfound")
}

fn to_block_id(block: &BlockSelector) -> BlockId {
    match block {
        BlockSelector::Latest => BlockId::Tag(BlockTag::Latest),
        BlockSelector::Pending => BlockId::Tag(BlockTag::PreConfirmed),
        BlockSelector::Number(number) => BlockId::Number(*number),
        BlockSelector::Hash(hash) => BlockId::Hash(core_felt_to_rs(hash.to_felt())),
    }
}

fn core_felt_to_rs(felt: CoreFelt) -> StarknetRsFelt {
    StarknetRsFelt::from_bytes_be(&felt.to_bytes_be())
}

fn rs_felt_to_core(felt: StarknetRsFelt) -> CoreFelt {
    CoreFelt::from_bytes_be(&felt.to_bytes_be())
}

fn rs_felt_to_biguint(felt: &StarknetRsFelt) -> BigUint {
    BigUint::from_bytes_be(&felt.to_bytes_be())
}
