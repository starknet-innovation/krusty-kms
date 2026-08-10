//! Account discovery: generate candidate account addresses from a mnemonic.
//!
//! Produces all possible Starknet account addresses for a mnemonic across
//! known wallet types and class hash versions. Performs no network I/O.

mod generate;
mod types;

#[cfg(test)]
mod tests;

pub use generate::{derive_discovery_keypairs, generate_candidates};
pub use types::{
    CandidateAccount, CandidateAccountWithSecrets, DerivationType, DerivedKeypair,
    DerivedKeypairWithSecrets, WalletType,
};
