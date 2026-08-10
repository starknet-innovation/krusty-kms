//! Braavos key derivation and address computation tests.

use crate::vectors::{
    BRAAVOS_ACCOUNT_ADDRESS, BRAAVOS_BASE_CLASS_HASH, BRAAVOS_PASSPHRASE, BRAAVOS_PRIVATE_KEY,
    BRAAVOS_PUBLIC_KEY, MNEMONIC,
};
use krusty_kms::{
    derive_private_key_with_coin_type, stark_public_key, AccountClass, BraavosAccount, SaltPolicy,
};
use starknet_types_core::felt::Felt;

// -- Key derivation -----------------------------------------------------------

/// Verify Braavos key derivation: direct BIP-44 with coin type 9004, no passphrase.
///
/// Braavos uses the simplest possible scheme — standard BIP-44 with the
/// Starknet coin type. No intermediate ETH key, no double derivation.
///
/// ```text
/// mnemonic
///   → PBKDF2 seed (passphrase = "")
///   → HMAC-SHA512("Bitcoin seed", seed) → master key
///   → BIP-32 derive m/44'/9004'/0'/0/0
///   → grindKey (SHA-256 rejection sampling mod Stark curve order)
///   → Stark private key
/// ```
#[test]
fn braavos_key_derivation_matches() {
    let pk = derive_private_key_with_coin_type(MNEMONIC, 0, 0, 9004, None).unwrap();
    let pubk = stark_public_key(&pk).unwrap();

    assert_eq!(
        pk,
        Felt::from_hex(BRAAVOS_PRIVATE_KEY).unwrap(),
        "Braavos private key = derive(mnemonic, coin=9004, idx=0, acct=0, passphrase=None)"
    );
    assert_eq!(
        pubk,
        Felt::from_hex(BRAAVOS_PUBLIC_KEY).unwrap(),
        "Braavos public key = stark_public_key(private_key)"
    );
}

/// Verify the Braavos UI "passphrase" is NOT used in BIP-39 seed generation.
///
/// This is a critical finding. Braavos shows a passphrase field in its UI,
/// but this passphrase is used for **wallet-level encryption** only — it
/// protects the stored seed at rest. It is NOT passed to PBKDF2 during
/// BIP-39 seed generation.
///
/// If you pass the passphrase to BIP-39, you get a completely different key
/// that does NOT match the on-chain account.
#[test]
fn braavos_passphrase_is_not_used_in_derivation() {
    // Correct: no passphrase → matches on-chain account
    let pk_no_pass = derive_private_key_with_coin_type(MNEMONIC, 0, 0, 9004, None).unwrap();
    assert_eq!(
        pk_no_pass,
        Felt::from_hex(BRAAVOS_PRIVATE_KEY).unwrap(),
        "Empty passphrase produces the correct Braavos key"
    );

    // Wrong: passing the UI passphrase → completely different key
    let pk_with_pass =
        derive_private_key_with_coin_type(MNEMONIC, 0, 0, 9004, Some(BRAAVOS_PASSPHRASE)).unwrap();
    assert_ne!(
        pk_with_pass,
        Felt::from_hex(BRAAVOS_PRIVATE_KEY).unwrap(),
        "Passing the Braavos UI passphrase to BIP-39 produces the WRONG key"
    );
}

// -- Address derivation -------------------------------------------------------

/// Verify Braavos address derivation with the **base deployment** class hash.
///
/// Braavos uses a proxy-like architecture:
/// 1. Accounts are deployed with a lightweight "base" contract
/// 2. On first transaction, the base contract upgrades itself to the full
///    implementation via `replace_class_syscall`
/// 3. The deployment address depends on the BASE class hash, not the full one
///
/// Constructor calldata is simply `[publicKey]` — no signer type enum,
/// no guardian. Salt is the public key.
///
/// ```text
/// address = computeHashOnElements([
///     "STARKNET_CONTRACT_ADDRESS",
///     deployer = 0,
///     salt = publicKey,
///     classHash = 0x03d16c7a...c201,   // base deployment hash
///     hash([publicKey])                  // constructor calldata hash
/// ])
/// ```
#[test]
fn braavos_address_derivation_matches() {
    let pubk = Felt::from_hex(BRAAVOS_PUBLIC_KEY).unwrap();
    let braavos = BraavosAccount::with_class_hash(Felt::from_hex(BRAAVOS_BASE_CLASS_HASH).unwrap());
    let addr = braavos
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    assert_eq!(
        addr,
        Felt::from_hex(BRAAVOS_ACCOUNT_ADDRESS).unwrap(),
        "Braavos address must match: salt=pubkey, class=base_hash, calldata=[pubkey], deployer=0"
    );
}

/// Verify that `BraavosAccount::new()` uses the correct base deployment hash.
///
/// The default class hash was updated from the legacy hash (`0x00816dd...`)
/// to the base deployment hash (`0x03d16c7a...c201`) based on this discovery.
#[test]
fn braavos_default_class_hash_produces_correct_address() {
    let pubk = Felt::from_hex(BRAAVOS_PUBLIC_KEY).unwrap();
    let braavos = BraavosAccount::new();
    let addr = braavos
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    assert_eq!(
        addr,
        Felt::from_hex(BRAAVOS_ACCOUNT_ADDRESS).unwrap(),
        "BraavosAccount::new() must use the base deployment class hash"
    );
}

/// Verify that the old/legacy Braavos class hash does NOT produce the right address.
///
/// The legacy hash (`0x00816dd...`) was the full implementation hash, not the
/// base deployment hash. Using it for address computation gives the wrong result.
#[test]
fn braavos_legacy_class_hash_produces_wrong_address() {
    let pubk = Felt::from_hex(BRAAVOS_PUBLIC_KEY).unwrap();
    let braavos_legacy = BraavosAccount::with_class_hash(
        Felt::from_hex(krusty_kms::BraavosAccount::LEGACY_CLASS_HASH).unwrap(),
    );
    let addr = braavos_legacy
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    assert_ne!(
        addr,
        Felt::from_hex(BRAAVOS_ACCOUNT_ADDRESS).unwrap(),
        "Legacy class hash (full implementation) does NOT produce the deployment address"
    );
}

// -- Multi-index discovery ----------------------------------------------------

/// Verify Braavos account discovery across multiple HD indices.
///
/// Wallets discover accounts by iterating `index = 0, 1, 2, ...`, deriving
/// the address at each index, and checking on-chain whether the contract is
/// deployed. This test verifies that each index produces a unique, non-zero
/// address and that index 0 matches the known test vector.
#[test]
fn braavos_multi_index_discovery() {
    let base_class = Felt::from_hex(BRAAVOS_BASE_CLASS_HASH).unwrap();
    let mut seen_addresses = Vec::new();

    for idx in 0..5u32 {
        let pk = derive_private_key_with_coin_type(MNEMONIC, idx, 0, 9004, None).unwrap();
        let pubk = stark_public_key(&pk).unwrap();
        let braavos = BraavosAccount::with_class_hash(base_class);
        let addr = braavos
            .calculate_address(&pubk, SaltPolicy::PublicKey)
            .unwrap();

        assert_ne!(
            addr,
            Felt::ZERO,
            "Address at index {} must be non-zero",
            idx
        );
        assert!(
            !seen_addresses.contains(&addr),
            "Address at index {} must be unique",
            idx
        );
        seen_addresses.push(addr);

        if idx == 0 {
            assert_eq!(
                addr,
                Felt::from_hex(BRAAVOS_ACCOUNT_ADDRESS).unwrap(),
                "Index 0 must match the known test vector"
            );
        }
    }
}
