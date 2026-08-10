//! Core multisig coordination types, message envelopes, and receive-side
//! validation.

use super::codec::{coordination_message_hash, hash_transaction_batch};
use super::encoding::{felt_to_hex, serde_address_hex, serde_felt_hex, serde_felt_hex_vec};
use crate::wallet::utils::{core_felt_to_rs, rs_felt_to_core};
use async_trait::async_trait;
use futures_util::Stream;
use krusty_kms_common::{Address, ChainId, KmsError, Result};
use serde::{Deserialize, Deserializer, Serialize};
use starknet_rust::core::crypto::{ecdsa_verify, Signature as StarkSignature};
use starknet_rust::core::types::Call;
use starknet_rust::signers::SigningKey;
use starknet_types_core::felt::Felt;
use std::pin::Pin;

/// Stream of coordination envelopes from a pub/sub backend.
pub type MultisigMessageStream =
    Pin<Box<dyn Stream<Item = Result<MultisigCoordinationEnvelope>> + Send>>;

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

/// Proposal payload distributed through a coordination server.
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

/// Logical coordination message exchanged through the coordinator.
///
/// On the wire, messages travel inside a [`MultisigCoordinationEnvelope`].
/// A bare (unsigned) message is advisory: the claimed
/// `signer`/`executor`/`proposer` is not authenticated by the coordinator, so
/// a compromised coordinator can forge notices. That is safe only because no
/// on-chain action is authorized by these messages — the multisig contract
/// re-checks quorum and signer authorization on-chain, and
/// [`Multisig::confirm_proposal`] re-derives the transaction id from the
/// proposal payload before signing. Consumers must treat unsigned notices as
/// hints (e.g. "check chain state"), never as proof that an action happened.
///
/// To authenticate the claimed actor cryptographically, wrap the message in a
/// [`SignedMultisigCoordinationMessage`] and verify it with
/// [`Multisig::verify_signed_message`] before tallying it.
///
/// [`Multisig::confirm_proposal`]: super::contract::Multisig::confirm_proposal
/// [`Multisig::verify_signed_message`]: super::contract::Multisig::verify_signed_message
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

    /// The account that claims to have performed (or proposed) the action.
    ///
    /// This attribution is unauthenticated unless the message arrived inside
    /// a verified [`SignedMultisigCoordinationMessage`].
    #[must_use]
    pub fn claimed_actor(&self) -> Address {
        match self {
            Self::Proposal(proposal) => proposal.proposer,
            Self::Confirmation(notice) | Self::Revocation(notice) => notice.signer,
            Self::Execution(notice) => notice.executor,
        }
    }

    /// Message kind discriminant bound into
    /// [`coordination_message_hash`](super::codec::coordination_message_hash).
    pub(super) fn kind_felt(&self) -> Felt {
        match self {
            Self::Proposal(_) => Felt::ONE,
            Self::Confirmation(_) => Felt::TWO,
            Self::Revocation(_) => Felt::THREE,
            Self::Execution(_) => Felt::from(4u64),
        }
    }
}

/// Schema version of [`SignedMultisigCoordinationMessage`].
///
/// Unsigned legacy messages are version 0 of the coordinator payload schema;
/// signed envelopes start at version 1. Bumping this constant requires a new
/// domain tag inside
/// [`coordination_message_hash`](super::codec::coordination_message_hash) so
/// signatures from one schema version can never validate under another.
pub const MULTISIG_COORDINATION_SCHEMA_VERSION: u32 = 1;

/// Coordination message authenticated by the claimed actor's account key.
///
/// The signature is a SNIP-6 style felt array over
/// [`coordination_message_hash`](super::codec::coordination_message_hash); for
/// Stark-key accounts it is `[r, s]` (see [`Self::sign_with_stark_key`]).
/// Other account types (e.g. secp256k1 signers) may carry their native
/// signature encoding — on-chain verification through the account's
/// `is_valid_signature` entrypoint stays account-agnostic.
///
/// Receivers must authenticate the envelope before tallying the notice:
/// [`Multisig::verify_signed_message`] checks the claimed actor against the
/// on-chain signer set and validates the signature through the actor's
/// account contract. [`Self::verify_with_stark_public_key`] offers an offline
/// check when the actor's Stark public key is already known and trusted.
///
/// [`Multisig::verify_signed_message`]: super::contract::Multisig::verify_signed_message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMultisigCoordinationMessage {
    /// Coordinator payload schema version; see
    /// [`MULTISIG_COORDINATION_SCHEMA_VERSION`].
    pub version: u32,
    /// The authenticated coordination message.
    pub message: MultisigCoordinationMessage,
    /// Signature over the coordination message hash, in the claimed actor's
    /// account signature format.
    #[serde(with = "serde_felt_hex_vec")]
    pub signature: Vec<Felt>,
}

impl SignedMultisigCoordinationMessage {
    /// Wrap a message with an externally produced account signature.
    ///
    /// Use this for account types whose signature is not a plain Stark
    /// `[r, s]` pair. The signature must cover the coordination message hash
    /// and must verify through the claimed actor's `is_valid_signature`
    /// entrypoint.
    pub fn new(message: MultisigCoordinationMessage, signature: Vec<Felt>) -> Result<Self> {
        if signature.is_empty() {
            return Err(KmsError::MultisigError(
                "signed coordination message requires a non-empty signature".to_string(),
            ));
        }
        Ok(Self {
            version: MULTISIG_COORDINATION_SCHEMA_VERSION,
            message,
            signature,
        })
    }

    /// Sign a message with a Stark-curve account key, producing `[r, s]`.
    pub fn sign_with_stark_key(
        message: MultisigCoordinationMessage,
        key: &SigningKey,
    ) -> Result<Self> {
        let hash = coordination_message_hash(&message);
        let signature = key
            .sign(&core_felt_to_rs(hash))
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;
        Self::new(
            message,
            vec![rs_felt_to_core(signature.r), rs_felt_to_core(signature.s)],
        )
    }

    /// The signing hash covering this envelope's message.
    #[must_use]
    pub fn message_hash(&self) -> Felt {
        coordination_message_hash(&self.message)
    }

    /// The account whose signature this envelope claims to carry.
    #[must_use]
    pub fn claimed_actor(&self) -> Address {
        self.message.claimed_actor()
    }

    /// Payload validation: supported schema version, non-empty signature, and
    /// — for proposals — that `transaction_id` recomputes from `calls`/`salt`.
    ///
    /// The proposal check lives here, not only on the coordinator receive
    /// path, because the signing hash covers `calls`/`salt` only transitively
    /// through `transaction_id`. Without recomputing the id, a coordinator
    /// could swap `calls`/`salt` while keeping the original id and signature,
    /// and the signature would still verify. Every verification entry point
    /// calls this first, so no path can attribute a tampered batch to a
    /// signer.
    ///
    /// This does **not** verify the signature cryptographically; use
    /// [`Multisig::verify_signed_message`] or
    /// [`Self::verify_with_stark_public_key`] for that.
    ///
    /// [`Multisig::verify_signed_message`]: super::contract::Multisig::verify_signed_message
    pub fn validate_structure(&self) -> Result<()> {
        if self.version != MULTISIG_COORDINATION_SCHEMA_VERSION {
            return Err(KmsError::MultisigError(format!(
                "unsupported signed coordination schema version {} (expected {})",
                self.version, MULTISIG_COORDINATION_SCHEMA_VERSION
            )));
        }
        if self.signature.is_empty() {
            return Err(KmsError::MultisigError(
                "signed coordination message carries an empty signature".to_string(),
            ));
        }
        if let MultisigCoordinationMessage::Proposal(proposal) = &self.message {
            proposal.validate_transaction_id()?;
        }
        Ok(())
    }

    /// Verify a Stark `[r, s]` signature against a known public key, offline.
    ///
    /// Runs [`Self::validate_structure`] first, so a proposal whose
    /// `transaction_id` does not recompute from `calls`/`salt` is rejected
    /// before the signature is considered.
    ///
    /// The caller is responsible for binding `public_key` to the claimed
    /// actor (e.g. from local key management or a prior authenticated
    /// exchange). When only the actor's address is known, use
    /// [`Multisig::verify_signed_message`], which resolves trust through the
    /// on-chain signer set and the actor's account contract instead.
    ///
    /// [`Multisig::verify_signed_message`]: super::contract::Multisig::verify_signed_message
    pub fn verify_with_stark_public_key(&self, public_key: Felt) -> Result<()> {
        self.validate_structure()?;
        let [r, s] = self.signature.as_slice() else {
            return Err(KmsError::MultisigError(format!(
                "expected a Stark [r, s] signature, got {} felts",
                self.signature.len()
            )));
        };
        let signature = StarkSignature {
            r: core_felt_to_rs(*r),
            s: core_felt_to_rs(*s),
        };
        let hash = core_felt_to_rs(self.message_hash());
        match ecdsa_verify(&core_felt_to_rs(public_key), &hash, &signature) {
            Ok(true) => Ok(()),
            Ok(false) => Err(KmsError::MultisigError(
                "coordination message signature does not verify against the given public key"
                    .to_string(),
            )),
            Err(error) => Err(KmsError::MultisigError(format!(
                "coordination message signature verification failed: {error}"
            ))),
        }
    }
}

/// Versioned wire envelope published to and received from coordinators.
///
/// Serialization is self-describing: a signed envelope carries
/// `version`/`message`/`signature` fields, while a legacy unsigned message is
/// the bare tagged [`MultisigCoordinationMessage`] (schema version 0).
/// Receivers should prefer signed envelopes and treat unsigned ones as
/// unauthenticated hints.
///
/// Deserialization discriminates on the *presence* of `version` rather than
/// trying each shape in turn: a payload carrying `version` must be a
/// well-formed signed envelope or it is rejected outright. Falling back to the
/// unsigned shape there would let a coordinator silently strip authentication
/// — moving `signature` to the top level, or setting an unsupported `version`
/// — and have the result accepted as a legacy hint instead of erroring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum MultisigCoordinationEnvelope {
    /// Schema version >= 1: message plus actor signature.
    Signed(SignedMultisigCoordinationMessage),
    /// Legacy schema version 0: unauthenticated message.
    Unsigned(MultisigCoordinationMessage),
}

impl<'de> Deserialize<'de> for MultisigCoordinationEnvelope {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Buffered as JSON because the coordination protocol is defined as
        // JSON on the wire, and `MultisigCoordinationMessage` is an
        // internally tagged enum that already requires a self-describing
        // format.
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.get("version").is_some() {
            let signed = SignedMultisigCoordinationMessage::deserialize(value)
                .map_err(serde::de::Error::custom)?;
            Ok(Self::Signed(signed))
        } else {
            let message = MultisigCoordinationMessage::deserialize(value)
                .map_err(serde::de::Error::custom)?;
            Ok(Self::Unsigned(message))
        }
    }
}

impl MultisigCoordinationEnvelope {
    /// The logical coordination message, regardless of authentication.
    #[must_use]
    pub fn message(&self) -> &MultisigCoordinationMessage {
        match self {
            Self::Signed(signed) => &signed.message,
            Self::Unsigned(message) => message,
        }
    }

    /// Topic used for pub/sub routing.
    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        self.message().topic()
    }

    /// The signed form, when this envelope carries a signature.
    ///
    /// This reports the envelope *shape* only. A signature supplied by an
    /// untrusted coordinator is not trustworthy until it is checked with
    /// [`Multisig::verify_signed_message`] or
    /// [`SignedMultisigCoordinationMessage::verify_with_stark_public_key`].
    ///
    /// [`Multisig::verify_signed_message`]: super::contract::Multisig::verify_signed_message
    #[must_use]
    pub fn as_signed(&self) -> Option<&SignedMultisigCoordinationMessage> {
        match self {
            Self::Signed(signed) => Some(signed),
            Self::Unsigned(_) => None,
        }
    }
}

impl From<MultisigCoordinationMessage> for MultisigCoordinationEnvelope {
    fn from(message: MultisigCoordinationMessage) -> Self {
        Self::Unsigned(message)
    }
}

impl From<SignedMultisigCoordinationMessage> for MultisigCoordinationEnvelope {
    fn from(signed: SignedMultisigCoordinationMessage) -> Self {
        Self::Signed(signed)
    }
}

/// Structural validation shared by the send and receive paths.
///
/// - a signed envelope must carry a supported schema version, a non-empty
///   signature, and a recomputable proposal `transaction_id`, and
/// - an unsigned proposal's `transaction_id` must recompute from its
///   `calls`/`salt` (defends against confirmations bound to a forged id).
///
/// Cryptographic signature verification needs on-chain state and lives in
/// [`Multisig::verify_signed_message`](super::contract::Multisig::verify_signed_message).
pub(super) fn validate_envelope_payload(envelope: &MultisigCoordinationEnvelope) -> Result<()> {
    if let MultisigCoordinationEnvelope::Signed(signed) = envelope {
        signed.validate_structure()?;
    }
    if let MultisigCoordinationMessage::Proposal(proposal) = envelope.message() {
        proposal.validate_transaction_id()?;
    }
    Ok(())
}

/// Receive-side validation for envelopes arriving from a coordinator.
///
/// The coordinator is a distribution boundary, not an authorization boundary:
/// nothing on the receive path is authenticated by the server. Every envelope
/// pulled from `subscribe`/`messages` must therefore be checked before it
/// drives an on-chain action:
///
/// - the message topic must match the subscribed topic (defends against
///   cross-topic replay/misrouting by a compromised coordinator), and
/// - the shared structural checks in [`validate_envelope_payload`].
pub(super) fn validate_incoming_envelope(
    topic: &MultisigTopic,
    envelope: &MultisigCoordinationEnvelope,
) -> Result<()> {
    if &envelope.topic() != topic {
        return Err(KmsError::MultisigError(
            "coordination message topic does not match the subscribed topic".to_string(),
        ));
    }
    validate_envelope_payload(envelope)
}

/// Coordination server boundary.
///
/// Implementations may use WebSockets, HTTP long polling, a durable message
/// bus, or any other pub/sub system. The server distributes messages and is
/// trusted for delivery only: on-chain multisig checks authorize every action,
/// and actor attribution is authenticated by
/// [`SignedMultisigCoordinationMessage`] rather than by the transport.
#[async_trait]
pub trait MultisigCoordinator: Send + Sync {
    /// Publish one coordination envelope.
    async fn publish(&self, envelope: MultisigCoordinationEnvelope) -> Result<()>;

    /// Return known envelopes for a transaction topic.
    async fn messages(&self, _topic: &MultisigTopic) -> Result<Vec<MultisigCoordinationEnvelope>> {
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
