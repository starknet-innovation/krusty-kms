//! Unit tests for BIP-44 derivation and its secret-returning variants.

use super::*;

const TEST_MNEMONIC: &str =
    "habit hope tip crystal because grunt nation idea electric witness alert like";

#[test]
fn test_derive_private_key() {
    let result = derive_private_key(TEST_MNEMONIC, 0, 0, None);
    assert!(result.is_ok());
}

#[test]
fn test_derive_keypair() {
    let keypair = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    assert_ne!(keypair.private_key, Felt::ZERO);
}

#[test]
fn test_deterministic_derivation() {
    let keypair1 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let keypair2 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();

    assert_eq!(keypair1.private_key, keypair2.private_key);
}

#[test]
fn test_different_indices_produce_different_keys() {
    let keypair0 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let keypair1 = derive_keypair(TEST_MNEMONIC, 1, 0, None).unwrap();

    assert_ne!(keypair0.private_key, keypair1.private_key);
}

#[test]
fn test_different_accounts_produce_different_keys() {
    let keypair_acc0 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let keypair_acc1 = derive_keypair(TEST_MNEMONIC, 0, 1, None).unwrap();

    assert_ne!(keypair_acc0.private_key, keypair_acc1.private_key);
}

#[test]
fn test_passphrase_changes_keys() {
    let without_passphrase = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let with_passphrase = derive_keypair(TEST_MNEMONIC, 0, 0, Some("test_passphrase")).unwrap();
    assert_ne!(without_passphrase.private_key, with_passphrase.private_key);
}

#[test]
fn test_empty_passphrase_same_as_none() {
    let with_none = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let with_empty = derive_keypair(TEST_MNEMONIC, 0, 0, Some("")).unwrap();
    assert_eq!(with_none.private_key, with_empty.private_key);
}

#[test]
fn test_derive_keypair_with_coin_type() {
    let keypair =
        derive_keypair_with_coin_type(TEST_MNEMONIC, 0, 0, TONGO_COIN_TYPE, None).unwrap();
    let standard = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    assert_eq!(keypair.private_key, standard.private_key);
}

#[test]
fn test_derive_keypair_with_starknet_coin_type() {
    let keypair =
        derive_keypair_with_coin_type(TEST_MNEMONIC, 0, 0, STARKNET_COIN_TYPE, None).unwrap();
    let tongo = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    // Different coin types should produce different keys
    assert_ne!(keypair.private_key, tongo.private_key);
}

#[test]
fn test_invalid_mnemonic() {
    let result = derive_keypair("invalid mnemonic words that are not valid", 0, 0, None);
    assert!(result.is_err());
}

#[test]
fn test_derive_nostr_private_key() {
    let result = derive_nostr_private_key(TEST_MNEMONIC, 0, 0, None);
    assert!(result.is_ok());
    let key = result.unwrap();
    assert_ne!(key, [0u8; 32]);
}

#[test]
fn test_derive_nostr_keypair() {
    let keypair = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    assert_ne!(keypair.private_key, [0u8; 32]);
    assert_ne!(keypair.public_key, [0u8; 32]);
}

#[test]
fn test_nostr_keypair_deterministic() {
    let keypair1 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let keypair2 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    assert_eq!(keypair1.private_key, keypair2.private_key);
    assert_eq!(keypair1.public_key, keypair2.public_key);
}

#[test]
fn test_nostr_different_indices() {
    let keypair0 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let keypair1 = derive_nostr_keypair(TEST_MNEMONIC, 1, 0, None).unwrap();
    assert_ne!(keypair0.private_key, keypair1.private_key);
}

#[test]
fn test_nostr_different_accounts() {
    let keypair_acc0 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let keypair_acc1 = derive_nostr_keypair(TEST_MNEMONIC, 0, 1, None).unwrap();
    assert_ne!(keypair_acc0.private_key, keypair_acc1.private_key);
}

#[test]
fn test_nostr_different_from_tongo() {
    // Nostr keys should be different from Tongo keys (different coin type, no grinding)
    let nostr = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let tongo = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();

    // Convert Felt to bytes for comparison
    let tongo_bytes = tongo.private_key.expose_secret().to_bytes_be();
    assert_ne!(nostr.private_key.as_slice(), tongo_bytes.as_slice());
}

#[test]
fn test_nostr_keypair_debug_redacts_private_key() {
    let keypair = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let debug = format!("{:?}", keypair);
    assert!(debug.contains("private_key: \"***\""));
    let priv_hex = hex::encode(keypair.private_key);
    assert!(!debug.contains(&priv_hex));
}

#[test]
fn test_nostr_passphrase_changes_keys() {
    let without = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let with = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, Some("test")).unwrap();
    assert_ne!(without.private_key, with.private_key);
}

#[test]
fn secret_variants_return_the_same_keys() {
    let secret = derive_secret_key_with_coin_type(TEST_MNEMONIC, 1, 2, STARKNET_COIN_TYPE, None);
    let plain = derive_private_key_with_coin_type(TEST_MNEMONIC, 1, 2, STARKNET_COIN_TYPE, None);
    assert_eq!(*secret.unwrap().expose_secret(), plain.unwrap());

    let secret = derive_argent_legacy_secret_key(TEST_MNEMONIC, 1, 0).unwrap();
    let plain = derive_argent_legacy_private_key(TEST_MNEMONIC, 1, 0).unwrap();
    assert_eq!(*secret.expose_secret(), plain);

    let eth_key = [9u8; 32];
    let secret = derive_stark_secret_key_from_eth_key(&eth_key, 3, 1).unwrap();
    let plain = derive_stark_from_eth_key(&eth_key, 3, 1).unwrap();
    assert_eq!(*secret.expose_secret(), plain);

    let seed = [7u8; 32];
    let secret = grind_secret_key(&seed).unwrap();
    assert_eq!(*secret.expose_secret(), grind_key(&seed).unwrap());

    let secret = derive_nostr_secret_key(TEST_MNEMONIC, 1, 2, Some("p")).unwrap();
    let plain = derive_nostr_private_key(TEST_MNEMONIC, 1, 2, Some("p")).unwrap();
    assert_eq!(*secret, plain);
}

#[test]
fn secret_variants_reject_what_the_plain_ones_reject() {
    let hardened = 0x8000_0000;
    assert!(derive_secret_key_with_coin_type(TEST_MNEMONIC, hardened, 0, 1, None).is_err());
    assert!(derive_secret_key_with_coin_type("not a mnemonic", 0, 0, 1, None).is_err());
    assert!(derive_argent_legacy_secret_key(TEST_MNEMONIC, hardened, 0).is_err());
    assert!(derive_nostr_secret_key(TEST_MNEMONIC, 0, hardened, None).is_err());
}
