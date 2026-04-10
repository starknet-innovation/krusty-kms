use crate::{map_kms_error, GatewayResult};
use async_trait::async_trait;
use krusty_kms_common::{
    is_already_deployed_validation_failure, ChainId, KmsError, NetworkPreset, SecretFelt,
};
use krusty_kms_domain::{
    AccountDescriptor, BlockSelector, DeployMode, FeltHex, GatewayError, GatewayErrorCode,
    SnapshotBlockMetadata, TrackedToken,
};
use num_bigint::BigUint;
use starknet_rust::accounts::{AccountFactory, AccountFactoryError, OpenZeppelinAccountFactory};
use starknet_rust::core::types::{
    BlockId, BlockTag, ExecutionResult, FunctionCall, MaybePreConfirmedBlockWithTxHashes,
    StarknetError, TransactionFinalityStatus, TransactionReceiptWithBlockInfo, TransactionStatus,
};
use starknet_rust::core::utils::get_selector_from_name;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::{Provider, ProviderError};
use starknet_rust::signers::{LocalWallet, SigningKey};
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

        let submission = factory
            .deploy_v3(core_felt_to_rs(account.salt.to_felt()))
            .send()
            .await
            .map_err(map_deploy_submission_error)?;

        let tx_hash = FeltHex::from_felt(rs_felt_to_core(submission.transaction_hash));
        match mode {
            DeployMode::SubmitOnly => Ok(DeployExecution::Submitted { tx_hash }),
            DeployMode::WaitForAcceptance(wait) => {
                wait_for_acceptance(
                    &self.provider,
                    submission.transaction_hash,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransactionObservation {
    Pending,
    Accepted,
    Reverted { reason: String },
}

async fn wait_for_acceptance(
    provider: &Arc<JsonRpcClient<HttpTransport>>,
    tx_hash: StarknetRsFelt,
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> Result<(), KmsError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let interval = Duration::from_millis(poll_interval_ms);

    loop {
        if Instant::now() >= deadline {
            return Err(KmsError::Timeout(format!(
                "transaction {} not accepted within {}ms",
                tx_hash, timeout_ms
            )));
        }

        match observe_transaction(provider, tx_hash).await? {
            TransactionObservation::Pending => tokio::time::sleep(interval).await,
            TransactionObservation::Accepted => return Ok(()),
            TransactionObservation::Reverted { reason } => {
                return Err(KmsError::TransactionReverted(format!(
                    "transaction {tx_hash:#x} reverted: {reason}"
                )))
            }
        }
    }
}

async fn observe_transaction(
    provider: &Arc<JsonRpcClient<HttpTransport>>,
    tx_hash: StarknetRsFelt,
) -> Result<TransactionObservation, KmsError> {
    match provider.get_transaction_receipt(tx_hash).await {
        Ok(receipt) => Ok(classify_receipt(&receipt)),
        Err(receipt_error) => match provider.get_transaction_status(tx_hash).await {
            Ok(status) => Ok(classify_transaction_status(&status)),
            Err(status_error) => {
                if is_transaction_hash_not_found(&receipt_error)
                    && is_transaction_hash_not_found(&status_error)
                {
                    Ok(TransactionObservation::Pending)
                } else {
                    Err(KmsError::RpcError(format!(
                        "failed to query transaction {tx_hash:#x}: receipt error: {receipt_error}; status error: {status_error}"
                    )))
                }
            }
        },
    }
}

fn classify_receipt(receipt: &TransactionReceiptWithBlockInfo) -> TransactionObservation {
    classify_execution(
        receipt.receipt.finality_status(),
        receipt.receipt.execution_result(),
    )
}

fn classify_transaction_status(status: &TransactionStatus) -> TransactionObservation {
    match status {
        TransactionStatus::Received | TransactionStatus::Candidate => {
            TransactionObservation::Pending
        }
        TransactionStatus::PreConfirmed(execution) => {
            classify_execution(&TransactionFinalityStatus::PreConfirmed, execution)
        }
        TransactionStatus::AcceptedOnL2(execution) => {
            classify_execution(&TransactionFinalityStatus::AcceptedOnL2, execution)
        }
        TransactionStatus::AcceptedOnL1(execution) => {
            classify_execution(&TransactionFinalityStatus::AcceptedOnL1, execution)
        }
    }
}

fn classify_execution(
    finality_status: &TransactionFinalityStatus,
    execution_result: &ExecutionResult,
) -> TransactionObservation {
    match execution_result {
        ExecutionResult::Reverted { reason } => TransactionObservation::Reverted {
            reason: reason.clone(),
        },
        ExecutionResult::Succeeded => match finality_status {
            TransactionFinalityStatus::PreConfirmed => TransactionObservation::Pending,
            TransactionFinalityStatus::AcceptedOnL2 | TransactionFinalityStatus::AcceptedOnL1 => {
                TransactionObservation::Accepted
            }
        },
    }
}

fn is_transaction_hash_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::TransactionHashNotFound)
    )
}

fn provider_transport_error(message: String) -> GatewayError {
    GatewayError::new(GatewayErrorCode::ProviderTransport, true, Some(message))
}

fn is_contract_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::ContractNotFound)
    )
}

fn is_entrypoint_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::EntrypointNotFound)
    )
}

async fn call_erc20_balance_with_selector_fallback(
    provider: &Arc<JsonRpcClient<HttpTransport>>,
    primary_call: FunctionCall,
    block_id: BlockId,
    fallback_call: FunctionCall,
) -> GatewayResult<Vec<StarknetRsFelt>> {
    match provider.call(primary_call, block_id).await {
        Ok(result) => Ok(result),
        Err(primary_error) if is_entrypoint_not_found(&primary_error) => {
            provider
                .call(fallback_call, block_id)
                .await
                .map_err(|fallback_error| {
                    provider_transport_error(format!(
                        "failed calling balance_of after typed entrypoint-not-found fallback: primary={primary_error}; fallback={fallback_error}"
                    ))
                })
        }
        Err(error) => Err(provider_transport_error(error.to_string())),
    }
}

fn map_deploy_submission_error<S: std::fmt::Display>(
    error: AccountFactoryError<S>,
) -> GatewayError {
    match error {
        AccountFactoryError::Provider(error) => map_deploy_provider_error(error),
        AccountFactoryError::Signing(error) => {
            map_kms_error(KmsError::CryptoError(error.to_string()))
        }
        AccountFactoryError::FeeOutOfRange => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some("fee calculation overflow".to_string()),
        ),
    }
}

fn map_deploy_provider_error(error: ProviderError) -> GatewayError {
    match error {
        ProviderError::StarknetError(error) => map_deploy_starknet_error(error),
        ProviderError::RateLimited => provider_transport_error("Request rate limited".to_string()),
        other => provider_transport_error(other.to_string()),
    }
}

fn map_deploy_starknet_error(error: StarknetError) -> GatewayError {
    match error {
        StarknetError::ClassHashNotFound => {
            map_kms_error(KmsError::InvalidClassHash("ClassHashNotFound".to_string()))
        }
        StarknetError::ContractNotFound => {
            map_kms_error(KmsError::ContractNotFound("ContractNotFound".to_string()))
        }
        StarknetError::InsufficientAccountBalance
        | StarknetError::InsufficientResourcesForValidate => {
            map_kms_error(KmsError::InsufficientFeeBalance(error.to_string()))
        }
        StarknetError::ValidationFailure(message) => {
            map_deploy_textual_starknet_error(message, GatewayErrorCode::InvalidRequest, false)
        }
        StarknetError::UnexpectedError(message) => {
            map_deploy_textual_starknet_error(message, GatewayErrorCode::RpcDegraded, true)
        }
        other => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(other.to_string()),
        ),
    }
}

fn map_deploy_textual_starknet_error(
    message: String,
    fallback_code: GatewayErrorCode,
    retryable: bool,
) -> GatewayError {
    if indicates_already_deployed(&message) {
        map_kms_error(KmsError::AlreadyDeployed(message))
    } else {
        GatewayError::new(fallback_code, retryable, Some(message))
    }
}

fn validate_open_zeppelin_descriptor(
    account: &AccountDescriptor,
    signing_key: &SigningKey,
) -> GatewayResult<()> {
    let derived_public_key = rs_felt_to_core(signing_key.verifying_key().scalar());
    if account.public_key.to_felt() != derived_public_key {
        return Err(GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(
                "account descriptor public key does not match the provided private key".to_string(),
            ),
        ));
    }

    let expected_calldata = [account.public_key.to_felt()];
    let actual_calldata: Vec<_> = account
        .constructor_calldata
        .iter()
        .map(FeltHex::to_felt)
        .collect();
    if actual_calldata != expected_calldata {
        return Err(GatewayError::new(
            GatewayErrorCode::ConstructorCalldataMismatch,
            false,
            Some(
                "OpenZeppelin deploy descriptor must use constructor calldata [public_key]"
                    .to_string(),
            ),
        ));
    }

    if account.deployer_address.to_felt() != CoreFelt::ZERO {
        return Err(GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some("OpenZeppelin deploy descriptor must use deployer_address = 0x0".to_string()),
        ));
    }

    Ok(())
}

fn indicates_already_deployed(message: &str) -> bool {
    is_already_deployed_validation_failure(message)
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

fn balance_of_selector() -> StarknetRsFelt {
    get_selector_from_name("balance_of").expect("literal selector name must be valid")
}

fn balance_of_camel_selector() -> StarknetRsFelt {
    get_selector_from_name("balanceOf").expect("literal selector name must be valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_preconfirmed_transactions_remain_pending() {
        assert_eq!(
            classify_execution(
                &TransactionFinalityStatus::PreConfirmed,
                &ExecutionResult::Succeeded,
            ),
            TransactionObservation::Pending
        );
    }

    #[test]
    fn accepted_success_is_reported_as_accepted() {
        assert_eq!(
            classify_transaction_status(&TransactionStatus::AcceptedOnL2(
                ExecutionResult::Succeeded,
            )),
            TransactionObservation::Accepted
        );
    }

    #[test]
    fn reverted_execution_is_terminal_before_acceptance() {
        assert_eq!(
            classify_transaction_status(&TransactionStatus::PreConfirmed(
                ExecutionResult::Reverted {
                    reason: "constructor failed".to_string(),
                },
            )),
            TransactionObservation::Reverted {
                reason: "constructor failed".to_string(),
            }
        );
    }

    #[test]
    fn received_and_candidate_transactions_are_pending() {
        assert_eq!(
            classify_transaction_status(&TransactionStatus::Received),
            TransactionObservation::Pending
        );
        assert_eq!(
            classify_transaction_status(&TransactionStatus::Candidate),
            TransactionObservation::Pending
        );
    }

    #[test]
    fn transaction_hash_not_found_is_treated_as_pending_lookup_state() {
        assert!(is_transaction_hash_not_found(
            &ProviderError::StarknetError(StarknetError::TransactionHashNotFound,)
        ));
        assert!(!is_transaction_hash_not_found(&ProviderError::RateLimited));
    }

    #[test]
    fn deploy_error_maps_typed_class_hash_failures_without_string_parsing() {
        let error = map_deploy_provider_error(ProviderError::StarknetError(
            StarknetError::ClassHashNotFound,
        ));
        assert_eq!(error.code, GatewayErrorCode::InvalidClassHash);
        assert!(!error.retryable);
    }

    #[test]
    fn deploy_error_maps_typed_fee_failures_without_string_parsing() {
        let error = map_deploy_provider_error(ProviderError::StarknetError(
            StarknetError::InsufficientAccountBalance,
        ));
        assert_eq!(error.code, GatewayErrorCode::InsufficientFee);
        assert!(!error.retryable);
    }

    #[test]
    fn deploy_validation_failure_still_recognizes_already_deployed_messages() {
        let error = map_deploy_starknet_error(StarknetError::ValidationFailure(
            "Requested ContractAddress has already been deployed".to_string(),
        ));
        assert_eq!(error.code, GatewayErrorCode::InvalidRequest);
        assert!(!error.retryable);
        assert_eq!(
            error.message.as_deref(),
            Some("Requested ContractAddress has already been deployed")
        );
    }

    #[test]
    fn deploy_check_treats_only_typed_contract_not_found_as_undeployed() {
        assert!(is_contract_not_found(&ProviderError::StarknetError(
            StarknetError::ContractNotFound,
        )));
        assert!(!is_contract_not_found(&ProviderError::RateLimited));
    }

    #[test]
    fn selector_fallback_only_triggers_on_typed_entrypoint_not_found() {
        assert!(is_entrypoint_not_found(&ProviderError::StarknetError(
            StarknetError::EntrypointNotFound,
        )));
        assert!(!is_entrypoint_not_found(&ProviderError::RateLimited));
    }

    #[test]
    fn selector_fallback_error_keeps_primary_and_fallback_context() {
        let error = provider_transport_error(format!(
            "failed calling balance_of after typed entrypoint-not-found fallback: primary={}; fallback={}",
            ProviderError::StarknetError(StarknetError::EntrypointNotFound),
            ProviderError::RateLimited,
        ));
        assert_eq!(error.code, GatewayErrorCode::ProviderTransport);
        let message = error
            .message
            .expect("provider transport errors include a message");
        assert!(message.contains("balance_of"));
        assert!(message.contains("primary="));
        assert!(message.contains("fallback="));
    }
}
