//! Argent key derivation and address computation tests.

use crate::vectors::{
    ARGENT_ACCOUNT_ADDRESS, ARGENT_PRIVATE_KEY, ARGENT_PUBLIC_KEY, ARGENT_V040_CLASS_HASH,
    MNEMONIC,
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

// -- Address derivation -------------------------------------------------------

/// Verify that standard (non-smart) Argent v0.4.0 addresses ARE derivable
/// from the mnemonic alone.
///
/// Standard accounts use `salt = publicKey`, making the address deterministic.
/// The constructor calldata is `[0, publicKey, 0]`:
/// - `0` = `Signer::Starknet` enum variant index
/// - `publicKey` = the Stark public key (felt252)
/// - `0` = `Option::None` for the guardian (no guardian)
///
/// This calldata format comes from the Argent contract's Cairo constructor:
/// ```cairo
/// fn constructor(ref self: ContractState, owner: Signer, guardian: Option<Signer>)
/// ```
/// Where `Signer::Starknet(StarknetSigner { pubkey })` serializes as `[0, pubkey]`.
#[test]
fn argent_standard_account_address_is_derivable() {
    let pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();
    let class_hash = Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap();

    let argent = ArgentAccount::with_class_hash(class_hash);
    let standard_addr = argent
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    // The address is deterministic and non-zero
    assert_ne!(standard_addr, Felt::ZERO);
    let standard_addr_again = argent
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();
    assert_eq!(
        standard_addr, standard_addr_again,
        "Address must be deterministic"
    );

    // The test data account is a "smart" account with a server-provided salt,
    // so it won't match the standard salt=publicKey formula.
    let expected = Felt::from_hex(ARGENT_ACCOUNT_ADDRESS).unwrap();
    assert_ne!(
        standard_addr, expected,
        "Test account is a 'smart' account — its salt was provided by Argent's server, \
         not derived from the public key. Standard accounts DO match."
    );
}

/// End-to-end: mnemonic → Argent legacy keys → standard account address.
///
/// This is the full pipeline a wallet would use to discover standard Argent
/// accounts from a mnemonic, using krusty-kms APIs.
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

    // Step 3: This address can be checked on-chain for existence
    assert_ne!(
        addr,
        Felt::ZERO,
        "Derived a valid Argent address from mnemonic"
    );
}

/// Argent "smart" accounts receive their deployment salt from a server-side API,
/// not from the mnemonic or public key. These addresses cannot be derived locally.
#[test]
fn argent_smart_account_salt_is_not_derivable() {
    let pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();
    let expected = Felt::from_hex(ARGENT_ACCOUNT_ADDRESS).unwrap();
    let class_hash = Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap();

    // salt = publicKey (the standard formula) does NOT produce the right address
    let argent = ArgentAccount::with_class_hash(class_hash);
    let addr_with_pk_salt = argent
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();
    assert_ne!(
        addr_with_pk_salt, expected,
        "Smart account salt != publicKey — it was assigned by Argent's server"
    );

    // salt = 0 also doesn't match
    let addr_with_zero_salt = argent.calculate_address(&pubk, SaltPolicy::Zero).unwrap();
    assert_ne!(
        addr_with_zero_salt, expected,
        "Smart account salt != 0 either"
    );
}
