//! OpenZeppelin Cairo multisig client and coordination primitives.
//!
//! The OpenZeppelin multisig is an on-chain governance contract, not an
//! off-chain signature aggregator. A coordination server is useful for
//! distributing proposals and signer status, but Starknet remains the source of
//! truth: every submit, confirm, revoke, and execute action is still sent
//! through a registered signer account.
//!
//! The coordinator is trusted for delivery only, never for authenticity. It is
//! a distribution boundary, not an authorization boundary: a compromised
//! coordinator can drop, reorder, replay, or forge payloads. Receivers
//! therefore re-derive transaction ids locally, check that messages match the
//! subscribed topic, and authenticate actor attribution through
//! [`SignedMultisigCoordinationMessage`].

mod actions;
mod codec;
mod contract;
mod encoding;
mod http;
mod in_memory;
#[cfg(feature = "nats")]
mod nats;
mod types;

#[cfg(test)]
mod tests;

use krusty_kms_common::{KmsError, Result};

pub(crate) type StarknetRsFelt = starknet_rust_core::types::Felt;

/// Largest coordinator payload a receiver will parse, for every transport.
///
/// The coordinator is untrusted on the receive path, so a single response or
/// message must not be able to exhaust the signer's memory before validation.
pub(crate) const MAX_COORDINATOR_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Largest envelope `publish` will send on any transport.
///
/// Two bytes below the receive cap: the HTTP `messages` endpoint returns a
/// JSON array, so a lone envelope comes back wrapped in `[` and `]` and
/// must still fit under [`MAX_COORDINATOR_PAYLOAD_BYTES`]. An HTTP history
/// page shares that cap among all of its envelopes, so several large ones
/// may still not fit on one page; the send-side bound only promises that an
/// envelope published alone is receivable.
pub(crate) const MAX_COORDINATOR_ENVELOPE_BYTES: usize = MAX_COORDINATOR_PAYLOAD_BYTES - 2;

/// Serialize an envelope for sending, refusing one no receiver would accept.
///
/// Both transports apply [`MAX_COORDINATOR_PAYLOAD_BYTES`] on receive, so a
/// larger envelope would publish successfully and then be dropped by every
/// peer running this SDK. Rejecting it here keeps a successful publish
/// deliverable.
pub(crate) fn encode_coordinator_payload(
    envelope: &MultisigCoordinationEnvelope,
) -> Result<Vec<u8>> {
    let payload =
        serde_json::to_vec(envelope).map_err(|error| KmsError::MultisigError(error.to_string()))?;
    if payload.len() > MAX_COORDINATOR_ENVELOPE_BYTES {
        return Err(KmsError::MultisigError(format!(
            "coordination envelope serializes to {} bytes, above the {MAX_COORDINATOR_ENVELOPE_BYTES} byte limit every receiver applies",
            payload.len()
        )));
    }
    Ok(payload)
}

pub use codec::{coordination_message_hash, hash_transaction, hash_transaction_batch};
pub use contract::Multisig;
pub use http::HttpMultisigCoordinator;
pub use in_memory::InMemoryMultisigCoordinator;
#[cfg(feature = "nats")]
pub use nats::NatsMultisigCoordinator;
pub use types::{
    MultisigCall, MultisigCoordinationEnvelope, MultisigCoordinationMessage, MultisigCoordinator,
    MultisigExecutionNotice, MultisigMessageStream, MultisigProposal, MultisigSignerNotice,
    MultisigTopic, MultisigTransactionState, SignedMultisigCoordinationMessage,
    MULTISIG_COORDINATION_SCHEMA_VERSION,
};
