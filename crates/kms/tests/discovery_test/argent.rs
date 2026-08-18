//! Argent key derivation and address computation tests.

use crate::vectors::{
    ARGENT_ACCOUNT_ADDRESS, ARGENT_PRIVATE_KEY, ARGENT_PUBLIC_KEY, ARGENT_V040_CLASS_HASH, MNEMONIC,
};
use krusty_kms::{
    derive_private_key_with_coin_type, stark_public_key, AccountClass, ArgentAccount, SaltPolicy,
};
use starknet_types_core::felt::Felt;

// -- Key derivation -----------------------------------------------------------

/// Verify Argent's "double derivation" produces the expected private and public keys.
///
/// Derivation: mnemonic → ETH key at m/44'/60'/0'/0/0 (raw, no grind) →
/// re-seed as BIP-32 master → m/44'/9004'/0'/0/0 → grindKey.
#[test]
fn argent_double_derivation_key_matches() {
    let stark_key = krusty_kms::derive_argent_legacy_private_key(MNEMONIC, 0, 0).unwrap();
    let stark_pubkey = stark_public_key(&stark_key).unwrap();

    assert_eq!(
        stark_key,
        Felt::from_hex(ARGENT_PRIVATE_KEY).unwrap(),
        "Private key must match the Argent double derivation: \
         mnemonic → raw ETH key (m/44'/60'/0'/0/0) → re-seed BIP-32 → m/44'/9004'/0'/0/0 → grindKey"
    );
    assert_eq!(
        stark_pubkey,
        Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap(),
        "Public key must match stark_public_key(private_key)"
    );
}

/// Confirm that Argent's derivation is NOT a simple direct `m/44'/9004'/0'/0/0`.
///
/// This test documents the incompatibility: a wallet using direct BIP-44
/// derivation (like Braavos) will derive a **different** key than old Argent
/// from the same mnemonic. Both wallets use coin type 9004 but the intermediate
/// ETH re-seeding step makes Argent's output completely different.
#[test]
fn argent_direct_derivation_does_not_match() {
    let pk_direct = derive_private_key_with_coin_type(MNEMONIC, 0, 0, 9004, None).unwrap();

    assert_ne!(
        pk_direct,
        Felt::from_hex(ARGENT_PRIVATE_KEY).unwrap(),
        "Direct m/44'/9004'/0'/0/0 produces a DIFFERENT key than old Argent. \
         This is the core vendor lock-in: Argent's double derivation via ETH \
         intermediate key makes its keys incompatible with direct BIP-44."
    );
}

// -- Address derivation -----------------------------------------------------

/// Standard accounts use `salt = publicKey`, so the address is deterministic and
/// must reproduce the account deployed on Sepolia for this mnemonic. See
/// `ArgentAccount::build_constructor_calldata` for why the guardian felt is `1`.
/// The mnemonic → address pipeline is gated in `candidates.rs`.
#[test]
fn argent_standard_account_address_matches_onchain() {
    let pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();
    let class_hash = Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap();

    let argent = ArgentAccount::with_class_hash(class_hash);

    assert_eq!(
        argent.build_constructor_calldata(&pubk),
        vec![Felt::ZERO, pubk, Felt::ONE],
        "v0.4.0 guardian must be Option::None (variant 1)"
    );

    let addr = argent
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    assert_eq!(
        addr,
        Felt::from_hex(ARGENT_ACCOUNT_ADDRESS).unwrap(),
        "Derived address must equal the account deployed on Sepolia for this mnemonic"
    );
}
