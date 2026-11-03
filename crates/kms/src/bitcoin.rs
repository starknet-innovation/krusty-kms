//! Bitcoin mainnet P2WPKH keys and signing: BIP-84 derivation, BIP-174 PSBT
//! input signing with BIP-143 sighashes, and BIP-322 "simple" messages.
//!
//! Inputs:
//! - a BIP-39 mnemonic and BIP-84 path components, or a raw 32-byte
//!   secp256k1 private key
//! - a base64 PSBT (version 0) with the inputs to sign, or a message and the
//!   key's own address
//!
//! Outputs:
//! - the keypair, its compressed public key, `bc1q…` address and path
//! - the PSBT with a partial signature added to each listed input
//! - the base64 BIP-322 simple witness
//!
//! Invariants:
//! - mainnet only: coin type 0 and the `bc` human-readable part
//! - signatures are deterministic RFC 6979 ECDSA, low-S, SIGHASH_ALL only
//! - a PSBT input is signed only when its `witness_utxo` pays this key's
//!   P2WPKH script and matches the output of the full `non_witness_utxo` it
//!   spends, so a lying amount cannot reach the sighash
//! - every other byte of the PSBT is preserved; nothing is finalized or
//!   broadcast
//! - malformed input fails closed with a [`krusty_kms_common::KmsError`]
//!
//! Everything here reuses the pure-Rust `k256` signer already used for Nostr.

mod bech32;
mod bip322;
mod keys;
mod psbt;
mod tx;

#[cfg(test)]
mod tests;

pub use bip322::sign_bip322_simple;
pub use keys::{derive_bitcoin_p2wpkh_keypair, BitcoinP2wpkhKeyPair, BITCOIN_COIN_TYPE};
pub use psbt::sign_bitcoin_psbt_inputs;
