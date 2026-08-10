//! Core multisig coordination types, message envelopes, and receive-side
//! validation.

use super::codec::hash_transaction_batch;
use super::encoding::{felt_to_hex, serde_address_hex, serde_felt_hex, serde_felt_hex_vec};
use crate::wallet::utils::{core_felt_to_rs, rs_felt_to_core};
use async_trait::async_trait;
use futures_util::Stream;
use krusty_kms_common::{Address, ChainId, KmsError, Result};
use serde::{Deserialize, Serialize};
use starknet_rust::core::types::Call;
use starknet_types_core::felt::Felt;
use std::pin::Pin;

/// Stream of coordination messages from a pub/sub backend.
pub type MultisigMessageStream =
    Pin<Box<dyn Stream<Item = Result<MultisigCoordinationMessage>> + Send>>;

/// Local representation of `starknet::account::Call` with stable JSON encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigCall {
    /// Target contract address.
    #[serde(with = "serde_address_hex")]
    pub to: Address,
    /// Entry point selector.
    #[serde(with = "serde_felt_hex")]
    pub selector: Felt,
    /// Raw Cairo calldata for the target call.
    #[serde(default, with = "serde_felt_hex_vec")]
    pub calldata: Vec<Felt>,
}

impl MultisigCall {
    /// Create a call from core Starknet types.
    #[must_use]
    pub fn new(to: Address, selector: Felt, calldata: Vec<Felt>) -> Self {
        Self {
            to,
            selector,
            calldata,
        }
    }

    /// Convert a `starknet-rs` call into the stable multisig call shape.
    #[must_use]
    pub fn from_starknet_call(call: &Call) -> Self {
        Self {
            to: Address::from(rs_felt_to_core(call.to)),
            selector: rs_felt_to_core(call.selector),
            calldata: call.calldata.iter().copied().map(rs_felt_to_core).collect(),
        }
    }

    /// Convert into the `starknet-rs` call shape used by wallet execution.
    #[must_use]
    pub fn to_starknet_call(&self) -> Call {
        Call {
            to: core_felt_to_rs(self.to.as_felt()),
            selector: core_felt_to_rs(self.selector),
            calldata: self.calldata.iter().copied().map(core_felt_to_rs).collect(),
        }
    }
}

/// State returned by `IMultisig::get_transaction_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultisigTransactionState {
    NotFound,
    Pending,
    Confirmed,
    Executed,
}

/// Pub/sub topic for one multisig transaction.
///
/// The chain is part of the routing key so a proposal replayed to a shared
/// coordinator cannot leak onto another network's topic, and a subscriber on
/// one chain never sees the other chain's messages for the same
/// multisig/transaction-id pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigTopic {
    #[serde(with = "serde_address_hex")]
    pub multisig: Address,
    pub chain_id: ChainId,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
}

impl MultisigTopic {
    #[must_use]
    pub(super) fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.chain_id,
            self.multisig.to_hex(),
            felt_to_hex(self.transaction_id)
        )
    }
}

/// Proposal payload distributed through a trusted coordination server.
///
/// `transaction_id` must equal [`hash_transaction_batch`] for `calls` and
/// `salt`. Receivers should call [`MultisigProposal::validate_transaction_id`]
/// before submitting confirmations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigProposal {
    #[serde(with = "serde_address_hex")]
    pub multisig: Address,
    /// Chain the proposal was created for. The transaction id hash covers
    /// only `calls`/`salt`, so without this field a proposal replayed through
    /// a shared or compromised coordinator would also validate on another
    /// network where the same multisig address/id exists.
    pub chain_id: ChainId,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
    pub calls: Vec<MultisigCall>,
    #[serde(with = "serde_felt_hex")]
    pub salt: Felt,
    #[serde(with = "serde_address_hex")]
    pub proposer: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

impl MultisigProposal {
    /// Build a proposal and compute the canonical OpenZeppelin transaction ID.
    ///
    /// The transaction id intentionally matches the on-chain hash (calls and
    /// salt only); the chain binding lives in the `chain_id` envelope field.
    #[must_use]
    pub fn new(
        multisig: Address,
        chain_id: ChainId,
        calls: Vec<MultisigCall>,
        salt: Felt,
        proposer: Address,
        memo: Option<String>,
    ) -> Self {
        let transaction_id = hash_transaction_batch(&calls, salt);
        Self {
            multisig,
            chain_id,
            transaction_id,
            calls,
            salt,
            proposer,
            memo,
        }
    }

    /// Return the coordination topic for this proposal.
    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        MultisigTopic {
            multisig: self.multisig,
            chain_id: self.chain_id,
            transaction_id: self.transaction_id,
        }
    }

    /// Recompute and validate the transaction ID.
    pub fn validate_transaction_id(&self) -> Result<()> {
        let expected = hash_transaction_batch(&self.calls, self.salt);
        if expected != self.transaction_id {
            return Err(KmsError::MultisigError(format!(
                "proposal transaction id {} does not match computed id {}",
                felt_to_hex(self.transaction_id),
                felt_to_hex(expected)
            )));
        }
        Ok(())
    }
}

/// Signer-scoped coordination notice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigSignerNotice {
    #[serde(with = "serde_address_hex")]
    pub multisig: Address,
    /// Chain this notice belongs to; part of the routing topic.
    pub chain_id: ChainId,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
    #[serde(with = "serde_address_hex")]
    pub signer: Address,
}

impl MultisigSignerNotice {
    #[must_use]
    pub fn new(
        multisig: Address,
        chain_id: ChainId,
        transaction_id: Felt,
        signer: Address,
    ) -> Self {
        Self {
            multisig,
            chain_id,
            transaction_id,
            signer,
        }
    }

    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        MultisigTopic {
            multisig: self.multisig,
            chain_id: self.chain_id,
            transaction_id: self.transaction_id,
        }
    }
}

/// Execution notice distributed after a signer submits execution on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigExecutionNotice {
    #[serde(with = "serde_address_hex")]
    pub multisig: Address,
    /// Chain this notice belongs to; part of the routing topic.
    pub chain_id: ChainId,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
    #[serde(with = "serde_address_hex")]
    pub executor: Address,
}

impl MultisigExecutionNotice {
    #[must_use]
    pub fn new(
        multisig: Address,
        chain_id: ChainId,
        transaction_id: Felt,
        executor: Address,
    ) -> Self {
        Self {
            multisig,
            chain_id,
            transaction_id,
            executor,
        }
    }

    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        MultisigTopic {
            multisig: self.multisig,
            chain_id: self.chain_id,
            transaction_id: self.transaction_id,
        }
    }
}

/// Message envelope exchanged through the trusted coordinator.
///
/// All variants are advisory: the claimed `signer`/`executor`/`proposer` is
/// not authenticated by the coordinator, so a compromised coordinator can
/// forge notices. This is safe only because no on-chain action is authorized
/// by these messages — the multisig contract re-checks quorum and signer
/// authorization on-chain, and [`Multisig::confirm_proposal`] re-derives the
/// transaction id from the proposal payload before signing. Consumers must
/// treat notices as hints (e.g. "check chain state"), never as proof that an
/// action happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MultisigCoordinationMessage {
    Proposal(MultisigProposal),
    Confirmation(MultisigSignerNotice),
    Revocation(MultisigSignerNotice),
    Execution(MultisigExecutionNotice),
}

impl MultisigCoordinationMessage {
    /// Topic used for pub/sub routing.
    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        match self {
            Self::Proposal(proposal) => proposal.topic(),
            Self::Confirmation(notice) | Self::Revocation(notice) => notice.topic(),
            Self::Execution(notice) => notice.topic(),
        }
    }
}

/// Receive-side validation for messages arriving from a coordinator.
///
/// The coordinator is a distribution boundary, not an authorization boundary:
/// nothing on the receive path is authenticated by the server. Every message
/// pulled from `subscribe`/`messages` must therefore be checked before it
/// drives an on-chain action:
///
/// - the message topic must match the subscribed topic (defends against
///   cross-topic replay/misrouting by a compromised coordinator), and
/// - a proposal's `transaction_id` must recompute from its `calls`/`salt`
///   (defends against confirmations bound to a forged id).
pub(super) fn validate_incoming_message(
    topic: &MultisigTopic,
    message: &MultisigCoordinationMessage,
) -> Result<()> {
    if &message.topic() != topic {
        return Err(KmsError::MultisigError(
            "coordination message topic does not match the subscribed topic".to_string(),
        ));
    }
    if let MultisigCoordinationMessage::Proposal(proposal) = message {
        proposal.validate_transaction_id()?;
    }
    Ok(())
}

/// Trusted coordination server boundary.
///
/// Implementations may use WebSockets, HTTP long polling, a durable message
/// bus, or any other trusted pub/sub system. The server distributes messages;
/// on-chain multisig checks still authorize every action.
#[async_trait]
pub trait MultisigCoordinator: Send + Sync {
    /// Publish one coordination message.
    async fn publish(&self, message: MultisigCoordinationMessage) -> Result<()>;

    /// Return known messages for a transaction topic.
    async fn messages(&self, _topic: &MultisigTopic) -> Result<Vec<MultisigCoordinationMessage>> {
        Err(KmsError::MultisigError(
            "coordinator does not expose retained message history".to_string(),
        ))
    }

    /// Subscribe to live pub/sub messages for a transaction topic.
    async fn subscribe(&self, _topic: &MultisigTopic) -> Result<MultisigMessageStream> {
        Err(KmsError::MultisigError(
            "coordinator does not expose live subscriptions".to_string(),
        ))
    }
}
