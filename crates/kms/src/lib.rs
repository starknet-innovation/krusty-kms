//! TONGO Key Management System (KMS).
//!
//! Provides BIP-44 compliant key derivation for TONGO accounts using custom coin type 5454.
//!
//! # Derivation Path
//!
//! The TONGO protocol uses the following BIP-44 derivation path:
//! ```text
//! m/44'/5454'/0'/0/{index}
//! ```
//!
//! Where:
//! - `44'` - BIP-44 purpose
//! - `5454'` - TONGO custom coin type
//! - `0'` - Account (hardened)
//! - `0` - Change (external chain)
//! - `{index}` - Address index

pub mod account;
pub mod account_class;
pub mod derivation;
pub mod eth_signer;
pub mod mnemonic;

pub use account::{calculate_contract_address, derive_oz_account_address};
pub use account_class::{
    AccountClass, ArgentAccount, BraavosAccount, OpenZeppelinAccount, OzAccountClassConfig,
    OzAccountClassSource, OzDeploymentDescriptor, SaltPolicy,
};
pub use derivation::{
    derive_keypair, derive_keypair_with_coin_type, derive_nostr_keypair, derive_nostr_private_key,
    derive_private_key, derive_private_key_with_coin_type, derive_view_keypair,
    derive_view_private_key, NostrKeyPair, TongoKeyPair, NOSTR_COIN_TYPE, STARKNET_COIN_TYPE,
    TONGO_COIN_TYPE, TONGO_VIEW_COIN_TYPE,
};
pub use eth_signer::EthSigner;
pub use krusty_kms_common::{
    AccountState, Address, Amount, AuditProof, ChainId, ElGamalCiphertext, ElGamalProof, KmsError,
    NetworkPreset, Poe2Proof, PoeProof, ProofOfBit, ProofOfTransfer, Range, Result, SecretFelt,
    SerializablePoint, Token, TransactionType, Validator,
};
pub use mnemonic::{generate_mnemonic, mnemonic_to_seed, validate_mnemonic};
