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

pub(crate) type StarknetRsFelt = starknet_rust::core::types::Felt;

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
