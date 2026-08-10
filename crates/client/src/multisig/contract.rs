//! Client handle for an OpenZeppelin Cairo multisig contract: construction and
//! read-path queries. On-chain action builders live in the sibling `actions`
//! module.

use super::codec::{
    read_address_span, read_bool, read_felt, read_transaction_state, read_u32, read_u64,
    serialize_batch_call_args, serialize_single_call_args,
};
use super::types::{MultisigCall, MultisigProposal, MultisigTransactionState};
use super::StarknetRsFelt;
use crate::abi;
use crate::wallet::utils::core_felt_to_rs;
use krusty_kms_common::{Address, ChainId, KmsError, Result};
use starknet_rust::core::types::{BlockId, BlockTag, Call, FunctionCall};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;
use starknet_types_core::felt::Felt;
use std::sync::Arc;

/// Client handle for an OpenZeppelin Cairo multisig contract.
pub struct Multisig {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    pub(super) address: Address,
    pub(super) chain_id: ChainId,
}

impl Multisig {
    /// Create a multisig contract handle.
    ///
    /// `chain_id` is the network the contract lives on; [`Self::confirm_proposal`]
    /// refuses to sign with a wallet bound to a different chain, so a proposal
    /// replayed across networks (the transaction id hash does not bind a chain)
    /// cannot collect confirmations there.
    #[must_use]
    pub fn new(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        address: Address,
        chain_id: ChainId,
    ) -> Self {
        Self {
            provider,
            address,
            chain_id,
        }
    }

    /// The multisig contract address.
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }

    /// The chain this handle expects the contract and signers to live on.
    #[must_use]
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Build a coordination proposal for a batch of calls.
    #[must_use]
    pub fn proposal(
        &self,
        calls: Vec<MultisigCall>,
        salt: Felt,
        proposer: Address,
        memo: Option<String>,
    ) -> MultisigProposal {
        MultisigProposal::new(self.address, self.chain_id, calls, salt, proposer, memo)
    }

    /// Query the current quorum.
    pub async fn get_quorum(&self) -> Result<u32> {
        let result = self.call(*abi::multisig::GET_QUORUM, vec![]).await?;
        read_u32(&result, "get_quorum")
    }

    /// Query whether an address is a signer.
    pub async fn is_signer(&self, signer: &Address) -> Result<bool> {
        let result = self
            .call(
                *abi::multisig::IS_SIGNER,
                vec![core_felt_to_rs(signer.as_felt())],
            )
            .await?;
        read_bool(&result, "is_signer")
    }

    /// Query the current signer list.
    pub async fn get_signers(&self) -> Result<Vec<Address>> {
        let result = self.call(*abi::multisig::GET_SIGNERS, vec![]).await?;
        read_address_span(&result, "get_signers")
    }

    /// Query whether a transaction reached quorum.
    pub async fn is_confirmed(&self, id: Felt) -> Result<bool> {
        let result = self
            .call(*abi::multisig::IS_CONFIRMED, vec![core_felt_to_rs(id)])
            .await?;
        read_bool(&result, "is_confirmed")
    }

    /// Query whether `signer` confirmed a transaction.
    pub async fn is_confirmed_by(&self, id: Felt, signer: &Address) -> Result<bool> {
        let result = self
            .call(
                *abi::multisig::IS_CONFIRMED_BY,
                vec![core_felt_to_rs(id), core_felt_to_rs(signer.as_felt())],
            )
            .await?;
        read_bool(&result, "is_confirmed_by")
    }

    /// Query whether a transaction has executed.
    pub async fn is_executed(&self, id: Felt) -> Result<bool> {
        let result = self
            .call(*abi::multisig::IS_EXECUTED, vec![core_felt_to_rs(id)])
            .await?;
        read_bool(&result, "is_executed")
    }

    /// Query the block number where a transaction was submitted.
    pub async fn get_submitted_block(&self, id: Felt) -> Result<u64> {
        let result = self
            .call(
                *abi::multisig::GET_SUBMITTED_BLOCK,
                vec![core_felt_to_rs(id)],
            )
            .await?;
        read_u64(&result, "get_submitted_block")
    }

    /// Query the current transaction state.
    pub async fn get_transaction_state(&self, id: Felt) -> Result<MultisigTransactionState> {
        let result = self
            .call(
                *abi::multisig::GET_TRANSACTION_STATE,
                vec![core_felt_to_rs(id)],
            )
            .await?;
        read_transaction_state(&result)
    }

    /// Query the count of confirmations from current registered signers.
    pub async fn get_transaction_confirmations(&self, id: Felt) -> Result<u32> {
        let result = self
            .call(
                *abi::multisig::GET_TRANSACTION_CONFIRMATIONS,
                vec![core_felt_to_rs(id)],
            )
            .await?;
        read_u32(&result, "get_transaction_confirmations")
    }

    /// Ask the contract to hash a single-call transaction.
    pub async fn hash_transaction_onchain(&self, call: &MultisigCall, salt: Felt) -> Result<Felt> {
        let result = self
            .call(
                *abi::multisig::HASH_TRANSACTION,
                serialize_single_call_args(call, salt),
            )
            .await?;
        read_felt(&result, "hash_transaction")
    }

    /// Ask the contract to hash a batch transaction.
    pub async fn hash_transaction_batch_onchain(
        &self,
        calls: &[MultisigCall],
        salt: Felt,
    ) -> Result<Felt> {
        let result = self
            .call(
                *abi::multisig::HASH_TRANSACTION_BATCH,
                serialize_batch_call_args(calls, salt),
            )
            .await?;
        read_felt(&result, "hash_transaction_batch")
    }

    pub(super) async fn call(
        &self,
        selector: StarknetRsFelt,
        calldata: Vec<StarknetRsFelt>,
    ) -> Result<Vec<StarknetRsFelt>> {
        self.provider
            .call(
                FunctionCall {
                    contract_address: core_felt_to_rs(self.address.as_felt()),
                    entry_point_selector: selector,
                    calldata,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|error| KmsError::RpcError(error.to_string()))
    }

    pub(super) fn call_to_multisig(
        &self,
        selector: StarknetRsFelt,
        calldata: Vec<StarknetRsFelt>,
    ) -> Call {
        Call {
            to: core_felt_to_rs(self.address.as_felt()),
            selector,
            calldata,
        }
    }
}
