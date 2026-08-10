//! On-chain multisig action builders and wallet-executed operations.

use super::codec::{
    serialize_batch_call_args, serialize_quorum_and_signers, serialize_single_call_args,
};
use super::contract::Multisig;
use super::types::{MultisigCall, MultisigProposal};
use crate::abi;
use crate::tx::Tx;
use crate::wallet::utils::core_felt_to_rs;
use crate::wallet::WalletExecutor;
use krusty_kms_common::{Address, KmsError, Result};
use starknet_rust::core::types::Call;
use starknet_types_core::felt::Felt;

impl Multisig {
    /// Build an `add_signers` self-admin call.
    #[must_use]
    pub fn populate_add_signers(&self, new_quorum: u32, signers_to_add: &[Address]) -> Call {
        self.call_to_multisig(
            *abi::multisig::ADD_SIGNERS,
            serialize_quorum_and_signers(new_quorum, signers_to_add),
        )
    }

    /// Build a `remove_signers` self-admin call.
    #[must_use]
    pub fn populate_remove_signers(&self, new_quorum: u32, signers_to_remove: &[Address]) -> Call {
        self.call_to_multisig(
            *abi::multisig::REMOVE_SIGNERS,
            serialize_quorum_and_signers(new_quorum, signers_to_remove),
        )
    }

    /// Build a `replace_signer` self-admin call.
    #[must_use]
    pub fn populate_replace_signer(
        &self,
        signer_to_remove: &Address,
        signer_to_add: &Address,
    ) -> Call {
        self.call_to_multisig(
            *abi::multisig::REPLACE_SIGNER,
            vec![
                core_felt_to_rs(signer_to_remove.as_felt()),
                core_felt_to_rs(signer_to_add.as_felt()),
            ],
        )
    }

    /// Build a `change_quorum` self-admin call.
    #[must_use]
    pub fn populate_change_quorum(&self, new_quorum: u32) -> Call {
        self.call_to_multisig(
            *abi::multisig::CHANGE_QUORUM,
            vec![core_felt_to_rs(Felt::from(new_quorum))],
        )
    }

    /// Build a `submit_transaction` call.
    #[must_use]
    pub fn populate_submit(&self, call: &MultisigCall, salt: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::SUBMIT_TRANSACTION,
            serialize_single_call_args(call, salt),
        )
    }

    /// Build a `submit_transaction_batch` call.
    #[must_use]
    pub fn populate_submit_batch(&self, calls: &[MultisigCall], salt: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::SUBMIT_TRANSACTION_BATCH,
            serialize_batch_call_args(calls, salt),
        )
    }

    /// Build a `confirm_transaction` call.
    #[must_use]
    pub fn populate_confirm(&self, id: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::CONFIRM_TRANSACTION,
            vec![core_felt_to_rs(id)],
        )
    }

    /// Build a `revoke_confirmation` call.
    #[must_use]
    pub fn populate_revoke(&self, id: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::REVOKE_CONFIRMATION,
            vec![core_felt_to_rs(id)],
        )
    }

    /// Build an `execute_transaction` call.
    #[must_use]
    pub fn populate_execute(&self, call: &MultisigCall, salt: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::EXECUTE_TRANSACTION,
            serialize_single_call_args(call, salt),
        )
    }

    /// Build an `execute_transaction_batch` call.
    #[must_use]
    pub fn populate_execute_batch(&self, calls: &[MultisigCall], salt: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::EXECUTE_TRANSACTION_BATCH,
            serialize_batch_call_args(calls, salt),
        )
    }

    /// Submit a batch proposal on-chain through a registered signer wallet.
    pub async fn submit_batch(
        &self,
        wallet: &dyn WalletExecutor,
        calls: &[MultisigCall],
        salt: Felt,
    ) -> Result<Tx> {
        wallet
            .execute(vec![self.populate_submit_batch(calls, salt)])
            .await
    }

    /// Confirm a submitted transaction on-chain through a registered signer wallet.
    ///
    /// `id` is trusted as-is and signed without any validation. **Do not** pass
    /// an id taken from a coordinator message: those arrive unauthenticated and
    /// a compromised coordinator can forge them. Use [`Self::confirm_proposal`]
    /// for coordinator-delivered proposals — it recomputes the id from the
    /// proposal payload and binds the multisig address and chain before
    /// signing. Reserve this method for ids from trusted sources (on-chain
    /// reads, locally constructed proposals).
    pub async fn confirm(&self, wallet: &dyn WalletExecutor, id: Felt) -> Result<Tx> {
        wallet.execute(vec![self.populate_confirm(id)]).await
    }

    /// Confirm a coordination proposal, validating it before signing.
    ///
    /// Rejects the confirmation when the proposal's `transaction_id` does not
    /// recompute from `calls`/`salt`, when the proposal targets a different
    /// multisig contract than this handle, when the proposal was created for a
    /// different chain, or when the signing wallet is bound to a different
    /// chain than this handle. This is the safe entry point for acting on
    /// coordinator-delivered proposals.
    pub async fn confirm_proposal(
        &self,
        wallet: &dyn WalletExecutor,
        proposal: &MultisigProposal,
    ) -> Result<Tx> {
        proposal.validate_transaction_id()?;
        if proposal.multisig != self.address {
            return Err(KmsError::MultisigError(format!(
                "proposal targets multisig {} but this handle is {}",
                proposal.multisig.to_hex(),
                self.address.to_hex()
            )));
        }
        if proposal.chain_id != self.chain_id {
            return Err(KmsError::MultisigError(format!(
                "proposal was created for chain {} but this handle is on {}",
                proposal.chain_id, self.chain_id
            )));
        }
        let wallet_chain = wallet.chain_id();
        if wallet_chain != self.chain_id {
            return Err(KmsError::MultisigError(format!(
                "wallet chain {} does not match multisig chain {}",
                wallet_chain, self.chain_id
            )));
        }
        self.confirm(wallet, proposal.transaction_id).await
    }

    /// Revoke a previous confirmation on-chain.
    pub async fn revoke(&self, wallet: &dyn WalletExecutor, id: Felt) -> Result<Tx> {
        wallet.execute(vec![self.populate_revoke(id)]).await
    }

    /// Execute a confirmed batch transaction on-chain.
    pub async fn execute_batch(
        &self,
        wallet: &dyn WalletExecutor,
        calls: &[MultisigCall],
        salt: Felt,
    ) -> Result<Tx> {
        wallet
            .execute(vec![self.populate_execute_batch(calls, salt)])
            .await
    }
}
