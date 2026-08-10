//! Client handle for an OpenZeppelin Cairo multisig contract: construction and
//! read-path queries. On-chain action builders live in the sibling `actions`
//! module.

use super::codec::{
    read_address_span, read_bool, read_felt, read_transaction_state, read_u32, read_u64,
    serialize_batch_call_args, serialize_single_call_args,
};
use super::types::{
    MultisigCall, MultisigProposal, MultisigTransactionState, SignedMultisigCoordinationMessage,
};
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

    /// Authenticate a signed coordination message against on-chain state.
    ///
    /// Verifies, in order:
    ///
    /// 1. envelope payload ([`SignedMultisigCoordinationMessage::validate_structure`]:
    ///    supported schema version, non-empty signature, and proposal
    ///    `transaction_id` recomputing from `calls`/`salt`),
    /// 2. the message targets this multisig contract and chain,
    /// 3. the claimed actor is currently in the on-chain signer set (the
    ///    OpenZeppelin multisig requires signers for confirm, revoke, and
    ///    execute alike, so this applies to every message kind),
    /// 4. the claimed actor's account contract accepts the signature over the
    ///    coordination message hash via SNIP-6 `is_valid_signature`.
    ///
    /// Returns the authenticated actor address on success.
    ///
    /// # What a verified envelope does and does not prove
    ///
    /// It proves the actor authorized *this exact message* — the routing
    /// topic, the message kind, and the attribution fields covered by the
    /// signing hash. It does not prove:
    ///
    /// - **Publisher identity.** Anyone holding a copy, including the
    ///   coordinator, can relay it.
    /// - **Freshness or uniqueness.** A valid envelope stays valid, so the
    ///   coordinator can replay it. Callers that tally notices must
    ///   deduplicate by `(actor, topic, message kind)` before counting, or a
    ///   single confirmation can be counted repeatedly.
    /// - **On-chain success.** Chain state remains authoritative for quorum
    ///   and execution; a notice is at most a hint to go read it.
    ///
    /// Both on-chain reads are pinned to one block, so signer-set membership
    /// and signature validity are decided against a single consistent
    /// snapshot: a signer removal or account upgrade landing mid-verification
    /// cannot be observed by one read but not the other. A removed signer's
    /// notices stop verifying once the removal lands on-chain.
    pub async fn verify_signed_message(
        &self,
        signed: &SignedMultisigCoordinationMessage,
    ) -> Result<Address> {
        signed.validate_structure()?;

        let topic = signed.message.topic();
        if topic.multisig != self.address {
            return Err(KmsError::MultisigError(format!(
                "signed message targets multisig {} but this handle is {}",
                topic.multisig.to_hex(),
                self.address.to_hex()
            )));
        }
        if topic.chain_id != self.chain_id {
            return Err(KmsError::MultisigError(format!(
                "signed message was created for chain {} but this handle is on {}",
                topic.chain_id, self.chain_id
            )));
        }

        // Pin both reads to one block so the membership check and the
        // signature check cannot straddle a signer removal or an account
        // upgrade. Hash rather than height: a reorg replacing the block would
        // otherwise silently change what the second read sees.
        let head = self
            .provider
            .block_hash_and_number()
            .await
            .map_err(|error| KmsError::RpcError(error.to_string()))?;
        let block_id = BlockId::Hash(head.block_hash);

        let actor = signed.claimed_actor();
        let signer_result = self
            .call_at_block(
                self.address,
                *abi::multisig::IS_SIGNER,
                vec![core_felt_to_rs(actor.as_felt())],
                block_id,
            )
            .await?;
        if !read_bool(&signer_result, "is_signer")? {
            return Err(KmsError::MultisigError(format!(
                "claimed actor {} is not a signer of multisig {}",
                actor.to_hex(),
                self.address.to_hex()
            )));
        }

        let mut calldata = Vec::with_capacity(signed.signature.len() + 2);
        calldata.push(core_felt_to_rs(signed.message_hash()));
        calldata.push(core_felt_to_rs(Felt::from(signed.signature.len() as u64)));
        calldata.extend(signed.signature.iter().copied().map(core_felt_to_rs));

        let result = self
            .call_at_block(actor, *abi::account::IS_VALID_SIGNATURE, calldata, block_id)
            .await?;
        let value = read_felt(&result, "is_valid_signature")?;
        // SNIP-6 accounts return the short string 'VALID'; some legacy
        // accounts return boolean 1.
        if value == Felt::from_bytes_be_slice(b"VALID") || value == Felt::ONE {
            Ok(actor)
        } else {
            Err(KmsError::MultisigError(format!(
                "account {} rejected the coordination message signature",
                actor.to_hex()
            )))
        }
    }

    pub(super) async fn call(
        &self,
        selector: StarknetRsFelt,
        calldata: Vec<StarknetRsFelt>,
    ) -> Result<Vec<StarknetRsFelt>> {
        self.call_at_block(
            self.address,
            selector,
            calldata,
            BlockId::Tag(BlockTag::Latest),
        )
        .await
    }

    async fn call_at_block(
        &self,
        contract: Address,
        selector: StarknetRsFelt,
        calldata: Vec<StarknetRsFelt>,
        block_id: BlockId,
    ) -> Result<Vec<StarknetRsFelt>> {
        self.provider
            .call(
                FunctionCall {
                    contract_address: core_felt_to_rs(contract.as_felt()),
                    entry_point_selector: selector,
                    calldata,
                },
                block_id,
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
