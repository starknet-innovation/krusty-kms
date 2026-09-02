//! Argent key derivation and address computation tests.

use crate::vectors::{
    ARGENT_ACCOUNT_ADDRESS, ARGENT_PRIVATE_KEY, ARGENT_PUBLIC_KEY, ARGENT_V040_CLASS_HASH, MNEMONIC,
};
use krusty_kms::{
    calculate_contract_address, derive_private_key_with_coin_type, stark_public_key, AccountClass,
    ArgentAccount, ArgentConstructorLayout, SaltPolicy,
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

// -- Address derivation -------------------------------------------------------

/// Verify that standard Argent v0.4.0 addresses are derivable from the public
/// key alone and reproduce a real on-chain account.
///
/// Standard accounts deploy with `salt = publicKey`, deployer `0`, and the
/// constructor calldata `[0, publicKey, 1]`:
/// - `0` = `Signer::Starknet` enum variant index
/// - `publicKey` = the Stark public key (felt252)
/// - `1` = `Option::None` for the guardian (Cairo serialises `None` as tag `1`)
///
/// From the Argent contract's Cairo constructor (v0.4.0):
/// ```cairo
/// fn constructor(ref self: ContractState, owner: Signer, guardian: Option<Signer>)
/// ```
/// where `Signer::Starknet(StarknetSigner { pubkey })` serialises as `[0, pubkey]`.
#[test]
fn argent_standard_account_address_matches_on_chain_vector() {
    let pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();
    let class_hash = Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap();
    let expected = Felt::from_hex(ARGENT_ACCOUNT_ADDRESS).unwrap();

    let argent = ArgentAccount::with_class_hash(class_hash);
    assert_eq!(
        argent.constructor_layout(),
        ArgentConstructorLayout::SignerWithOptionalGuardian
    );
    let addr = argent
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();
    assert_eq!(
        addr, expected,
        "salt = publicKey with calldata [0, pk, 1] must reproduce the deployed Argent v0.4.0 account"
    );
    // The same address falls out of the default (v0.4.0) preset.
    assert_eq!(
        ArgentAccount::new()
            .calculate_address(&pubk, SaltPolicy::PublicKey)
            .unwrap(),
        expected
    );
}

/// Regression: encoding the absent guardian as `0` (the `Option::Some` tag with
/// no payload) produced an address that no Argent class can ever deploy to.
#[test]
fn argent_guardian_some_tag_regression_does_not_match() {
    let pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();
    let class_hash = Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap();
    let expected = Felt::from_hex(ARGENT_ACCOUNT_ADDRESS).unwrap();

    let broken_calldata = [Felt::ZERO, pubk, Felt::ZERO];
    let broken =
        calculate_contract_address(&pubk, &class_hash, &broken_calldata, &Felt::ZERO).unwrap();
    assert_ne!(
        broken, expected,
        "[0, pk, 0] is not a valid Argent v0.4.0 constructor payload"
    );
}

/// A zero salt is not the standard Argent deployment and must not match.
#[test]
fn argent_zero_salt_does_not_match_standard_account() {
    let pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();
    let expected = Felt::from_hex(ARGENT_ACCOUNT_ADDRESS).unwrap();
    let argent = ArgentAccount::with_class_hash(Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap());
    let addr = argent.calculate_address(&pubk, SaltPolicy::Zero).unwrap();
    assert_ne!(addr, expected);
}

/// End-to-end: mnemonic → Argent legacy keys → standard account address that
/// exists on chain.
#[test]
fn argent_standard_discovery_end_to_end() {
    // Step 1: Derive keys using Argent's double derivation
    let pk = krusty_kms::derive_argent_legacy_private_key(MNEMONIC, 0, 0).unwrap();
    let pubk = stark_public_key(&pk).unwrap();
    assert_eq!(pubk, Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap());

    // Step 2: Compute the standard account address
    let argent = ArgentAccount::with_class_hash(Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap());
    let addr = argent
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    // Step 3: It is the deployed account recorded in the vectors.
    assert_eq!(addr, Felt::from_hex(ARGENT_ACCOUNT_ADDRESS).unwrap());
}

/// Argent v0.3.x classes take `(owner: felt252, guardian: felt252)`; the
/// preset selects that layout from the class hash.
#[test]
fn argent_v03_class_hashes_select_felt_layout() {
    let pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();
    for hash in [
        ArgentAccount::CLASS_HASH_V030,
        ArgentAccount::CLASS_HASH_V031,
    ] {
        let argent = ArgentAccount::with_class_hash(Felt::from_hex(hash).unwrap());
        assert_eq!(
            argent.constructor_layout(),
            ArgentConstructorLayout::OwnerGuardianFelts
        );
        assert_eq!(
            argent.build_constructor_calldata(&pubk),
            vec![pubk, Felt::ZERO]
        );
    }
}
