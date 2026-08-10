//! OpenZeppelin Cairo multisig client and trusted coordination primitives.
//!
//! The OpenZeppelin multisig is an on-chain governance contract, not an
//! off-chain signature aggregator. A coordination server is useful for
//! distributing proposals and signer status, but Starknet remains the source of
//! truth: every submit, confirm, revoke, and execute action is still sent
//! through a registered signer account.

mod actions;
mod codec;
mod contract;
mod encoding;
mod http;
mod in_memory;
mod nats;
mod types;

#[cfg(test)]
mod tests;

pub(crate) type StarknetRsFelt = starknet_rust::core::types::Felt;

pub use codec::{hash_transaction, hash_transaction_batch};
pub use contract::Multisig;
pub use http::HttpMultisigCoordinator;
pub use in_memory::InMemoryMultisigCoordinator;
pub use nats::NatsMultisigCoordinator;
pub use types::{
    MultisigCall, MultisigCoordinationMessage, MultisigCoordinator, MultisigExecutionNotice,
    MultisigMessageStream, MultisigProposal, MultisigSignerNotice, MultisigTopic,
    MultisigTransactionState,
};
