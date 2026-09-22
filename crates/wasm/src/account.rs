//! WASM bindings for Tongo account management.
//!
//! Provides account creation, key derivation, and state management
//! functionality accessible from JavaScript/TypeScript.

mod addresses;
mod derivation;
mod helpers;
mod nostr;
mod wasm_account;

#[cfg(test)]
mod tests;

pub use addresses::{
    calculate_contract_address, derive_argent_account_address, derive_braavos_account_address,
    derive_oz_account_address, get_account_class_hashes,
};
pub use derivation::{
    derive_argent_legacy_keypair, derive_argent_legacy_public_key, derive_keypair,
    derive_public_key, derive_starknet_keypair, derive_starknet_public_key, generate_mnemonic,
    get_nostr_coin_type, get_starknet_coin_type, get_tongo_coin_type, validate_mnemonic,
};
pub use nostr::{derive_nostr_keypair, derive_nostr_public_key};
pub use wasm_account::WasmAccount;
