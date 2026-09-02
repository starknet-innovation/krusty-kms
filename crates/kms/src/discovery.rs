//! Account discovery: generate candidate account addresses from a mnemonic.
//!
//! Produces all possible Starknet account addresses for a mnemonic across
//! known wallet types and class hash versions. Performs no network I/O.

mod generate;
mod types;

#[cfg(test)]
mod tests;

/// Upper bound on the `max_index` accepted by the discovery entry points.
///
/// `max_index` is caller-controlled at the WASM and FFI boundaries and every
/// index costs two BIP-39 seed derivations (2048 PBKDF2 rounds each) plus
/// address computations, so an unbounded value is a CPU-exhaustion vector and
/// `u32::MAX` overflowed the pre-allocation arithmetic. Recovery scans need
/// far fewer indices than this.
pub const MAX_DISCOVERY_INDEX: u32 = 1024;

pub use generate::{derive_discovery_keypairs, generate_candidates};
pub use types::{
    CandidateAccount, CandidateAccountWithSecrets, DerivationType, DerivedKeypair,
    DerivedKeypairWithSecrets, WalletType,
};
