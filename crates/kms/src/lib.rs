//! Deterministic key derivation, account descriptors, and Stark/Nostr signing.

pub mod account;
pub mod account_class;
pub mod derivation;
pub mod discovery;
pub mod encryption;
pub mod eth_signer;
pub mod keystore;
pub mod mnemonic;
pub mod nostr_signing;
pub mod stark_signing;
pub mod strk20;
pub mod tx_hash;
pub mod typed_data;

pub use account::{
    calculate_contract_address, derive_oz_account_address, encode_short_string, hash_elements,
};
pub use account_class::{
    AccountClass, ArgentAccount, BraavosAccount, OpenZeppelinAccount, OzAccountClassConfig,
    OzAccountClassSource, OzDeploymentDescriptor, SaltPolicy,
};
pub use derivation::{
    derive_argent_legacy_private_key, derive_keypair, derive_keypair_with_coin_type,
    derive_nostr_keypair, derive_nostr_private_key, derive_private_key,
    derive_private_key_with_coin_type, derive_stark_from_eth_key, grind_key, NostrKeyPair,
    TongoKeyPair, NOSTR_COIN_TYPE, STARKNET_COIN_TYPE, TONGO_COIN_TYPE,
};
pub use discovery::{
    derive_discovery_keypairs, generate_candidates, CandidateAccount, DerivationType,
    DerivedKeypair, WalletType,
};
pub use encryption::{
    decrypt_private_key, decrypt_with_key, encrypt_private_key, encrypt_with_key, EncryptedKey,
    EncryptedPayload,
};
pub use eth_signer::EthSigner;
pub use keystore::{decrypt_ethers_keystore, decrypt_keystore, encrypt_keystore};
pub use mnemonic::{generate_mnemonic, mnemonic_to_seed, validate_mnemonic};
pub use nostr_signing::{
    nostr_public_key, sign_nostr_event_id, sign_nostr_message, NostrEventSignature, NostrSignature,
};
pub use stark_signing::{sign_stark_hash, stark_public_key, StarkSignature};
pub use strk20::{derive_strk20_viewing_key, STRK20_VIEWING_KEY_DOMAIN};
pub use tx_hash::{
    compute_declare_v2_hash, compute_declare_v3_hash, compute_deploy_account_v1_hash,
    compute_deploy_account_v3_hash, compute_invoke_v1_hash, compute_invoke_v3_hash,
    compute_invoke_v3_hash_with_proof_facts, DaMode, ResourceBounds,
};
pub use typed_data::compute_typed_data_message_hash;
