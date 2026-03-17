//! TONGO SDK - Confidential Transactions on Starknet.
//!
//! This SDK provides high-level APIs for interacting with the TONGO protocol:
//! - Account management
//! - Fund operations (deposit to confidential balance)
//! - Transfer operations (confidential transfers)
//! - Rollover operations (activate pending balance)
//! - Withdraw operations (exit to public balance)
//!
//! All TONGO account operations in this SDK use a single account key derived
//! from coin type 5454. For transfers, pass the recipient's TONGO public key in
//! `TransferParams::recipient_public_key` so the recipient can decrypt the
//! confidential payload with their account key.

pub mod account;
pub mod crypto;
pub mod operations;
pub mod serialization;

pub use account::TongoAccount;
pub use crypto::{decrypt_as_auditor, encrypt_for_auditor};
pub use krusty_kms::{
    calculate_contract_address, derive_keypair, derive_keypair_with_coin_type,
    derive_nostr_keypair, derive_nostr_private_key, derive_oz_account_address, derive_private_key,
    derive_private_key_with_coin_type, generate_mnemonic, mnemonic_to_seed, validate_mnemonic,
    AccountClass, ArgentAccount, BraavosAccount, EthSigner, NostrKeyPair, OpenZeppelinAccount,
    OzAccountClassConfig, OzAccountClassSource, OzDeploymentDescriptor, SaltPolicy, TongoKeyPair,
    NOSTR_COIN_TYPE, STARKNET_COIN_TYPE, TONGO_COIN_TYPE,
};
pub use krusty_kms_common::{
    AccountState, AuditProof, ElGamalCiphertext, ElGamalProof, KmsError, Poe2Proof, PoeProof,
    ProofOfBit, ProofOfTransfer, Range, Result, SecretFelt, SerializablePoint, TransactionType,
};
pub use krusty_kms_crypto::{
    fill_random_bytes, poseidon_hash_many, random_felt, random_felts, AuditPrefixData, AuditProver,
    ElGamal, ElGamalEncryption, ProofOfExponentiation, ProofOfExponentiation2, StarkCurve,
};
pub use operations::{fund, ragequit, rollover, transfer, withdraw};
