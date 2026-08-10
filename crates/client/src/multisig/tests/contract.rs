//! `Multisig::confirm_proposal` validation against a recording wallet executor.

use super::{address, call, confirmation_notice, test_signing_key};
use crate::multisig::{
    Multisig, MultisigCoordinationMessage, MultisigProposal, SignedMultisigCoordinationMessage,
    MULTISIG_COORDINATION_SCHEMA_VERSION,
};
use crate::tx::Tx;
use crate::wallet::WalletExecutor;
use async_trait::async_trait;
use krusty_kms_common::{Address, ChainId, KmsError, Result};
use starknet_rust::core::types::Call;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_types_core::felt::Felt;
use std::sync::Arc;
use url::Url;

struct RecordingExecutor {
    network: krusty_kms_common::network::NetworkPreset,
    wallet_address: Address,
    chain_id: ChainId,
    executed: std::sync::Mutex<Vec<Vec<Call>>>,
}

impl RecordingExecutor {
    fn sepolia(wallet_address: Address) -> Self {
        Self {
            network: krusty_kms_common::network::NetworkPreset::sepolia(),
            wallet_address,
            chain_id: ChainId::Sepolia,
            executed: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn executed_count(&self) -> usize {
        self.executed.lock().unwrap().len()
    }
}

#[async_trait]
impl WalletExecutor for RecordingExecutor {
    async fn execute(&self, calls: Vec<Call>) -> Result<Tx> {
        self.executed.lock().unwrap().push(calls);
        Err(KmsError::CryptoError("recorded".to_string()))
    }

    async fn estimate_fee(
        &self,
        _calls: Vec<Call>,
    ) -> Result<starknet_rust::core::types::FeeEstimate> {
        unreachable!("confirm_proposal tests never estimate fees")
    }

    fn address(&self) -> &Address {
        &self.wallet_address
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn network(&self) -> &krusty_kms_common::network::NetworkPreset {
        &self.network
    }

    async fn is_deployed(&self) -> Result<bool> {
        Ok(true)
    }
}

fn test_multisig_handle(address_value: u64) -> Multisig {
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse("http://127.0.0.1:0").unwrap(),
    )));
    Multisig::new(provider, address(address_value), ChainId::Sepolia)
}

#[tokio::test]
async fn test_verify_signed_message_prevalidation() {
    // These rejections trigger before any RPC call, so a handle with an
    // unroutable provider exercises them deterministically.
    let multisig = test_multisig_handle(1);
    let key = test_signing_key(0x1234);
    let signed =
        SignedMultisigCoordinationMessage::sign_with_stark_key(confirmation_notice(3), &key)
            .unwrap();

    // Unsupported schema version.
    let mut wrong_version = signed.clone();
    wrong_version.version = 0;
    assert!(matches!(
        multisig.verify_signed_message(&wrong_version).await,
        Err(KmsError::MultisigError(_))
    ));

    // Message bound to a different multisig contract.
    let foreign_multisig = test_multisig_handle(9);
    assert!(matches!(
        foreign_multisig.verify_signed_message(&signed).await,
        Err(KmsError::MultisigError(_))
    ));

    // Message bound to a different chain.
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse("http://127.0.0.1:0").unwrap(),
    )));
    let mainnet_handle = Multisig::new(provider, address(1), ChainId::Mainnet);
    assert!(matches!(
        mainnet_handle.verify_signed_message(&signed).await,
        Err(KmsError::MultisigError(_))
    ));

    // Signed proposal whose transaction id does not recompute.
    let mut forged_proposal = MultisigProposal::new(
        address(1),
        ChainId::Sepolia,
        vec![call()],
        Felt::from(99u64),
        address(2),
        None,
    );
    forged_proposal.transaction_id = Felt::from(1u64);
    let forged = SignedMultisigCoordinationMessage {
        version: MULTISIG_COORDINATION_SCHEMA_VERSION,
        message: MultisigCoordinationMessage::Proposal(forged_proposal),
        signature: signed.signature.clone(),
    };
    assert!(matches!(
        multisig.verify_signed_message(&forged).await,
        Err(KmsError::MultisigError(_))
    ));
}

#[tokio::test]
async fn test_confirm_proposal_reaches_executor_with_recomputed_id() {
    let multisig = test_multisig_handle(1);
    let executor = RecordingExecutor::sepolia(address(2));
    let proposal = multisig.proposal(vec![call()], Felt::from(99u64), address(2), None);

    let result = multisig.confirm_proposal(&executor, &proposal).await;
    assert!(matches!(result, Err(KmsError::CryptoError(_))));
    let executed = executor.executed.lock().unwrap();
    assert_eq!(
        executed.as_slice(),
        &[vec![multisig.populate_confirm(proposal.transaction_id)]]
    );
}

#[tokio::test]
async fn test_confirm_proposal_rejects_forged_transaction_id() {
    let multisig = test_multisig_handle(1);
    let executor = RecordingExecutor::sepolia(address(2));
    let mut forged = multisig.proposal(vec![call()], Felt::from(99u64), address(2), None);
    forged.transaction_id = Felt::from(1u64);

    assert!(matches!(
        multisig.confirm_proposal(&executor, &forged).await,
        Err(KmsError::MultisigError(_))
    ));
    assert_eq!(executor.executed_count(), 0);
}

#[tokio::test]
async fn test_confirm_proposal_rejects_foreign_multisig() {
    let multisig = test_multisig_handle(1);
    let executor = RecordingExecutor::sepolia(address(2));
    let foreign = MultisigProposal::new(
        address(77),
        ChainId::Sepolia,
        vec![call()],
        Felt::from(99u64),
        address(2),
        None,
    );

    assert!(matches!(
        multisig.confirm_proposal(&executor, &foreign).await,
        Err(KmsError::MultisigError(_))
    ));
    assert_eq!(executor.executed_count(), 0);
}

#[tokio::test]
async fn test_confirm_proposal_rejects_wallet_on_wrong_chain() {
    // The transaction id hash binds calls and salt but no chain, so a
    // replayed proposal must be stopped at the chain check instead.
    let multisig = test_multisig_handle(1);
    let mut executor = RecordingExecutor::sepolia(address(2));
    executor.chain_id = ChainId::Mainnet;
    let proposal = multisig.proposal(vec![call()], Felt::from(99u64), address(2), None);

    assert!(matches!(
        multisig.confirm_proposal(&executor, &proposal).await,
        Err(KmsError::MultisigError(_))
    ));
    assert_eq!(executor.executed_count(), 0);
}

#[tokio::test]
async fn test_confirm_proposal_rejects_proposal_from_wrong_chain() {
    // A proposal created for mainnet replayed through the coordinator to
    // a Sepolia handle must be rejected even when address and id match.
    let multisig = test_multisig_handle(1);
    let executor = RecordingExecutor::sepolia(address(2));
    let mut proposal = multisig.proposal(vec![call()], Felt::from(99u64), address(2), None);
    proposal.chain_id = ChainId::Mainnet;

    assert!(matches!(
        multisig.confirm_proposal(&executor, &proposal).await,
        Err(KmsError::MultisigError(_))
    ));
    assert_eq!(executor.executed_count(), 0);
}
