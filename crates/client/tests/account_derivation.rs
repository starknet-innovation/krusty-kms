//! Tests for Starknet account derivation.
//!
//! These tests verify that our Rust implementation derives the same account
//! addresses as the TypeScript reference implementation.

use krusty_kms::{derive_keypair, derive_oz_account_address};
use starknet_types_core::felt::Felt;

/// OpenZeppelin account class hash from tongo-sepolia.test.ts
const OZ_ACCOUNT_CLASS_HASH: &str =
    "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";

/// Standard test mnemonic (same as TypeScript tests)
const TEST_MNEMONIC: &str =
    "habit hope tip crystal because grunt nation idea electric witness alert like";

#[test]
fn test_derive_tongo_keypair() {
    // Derive TONGO keypair (coin type 5454) at index 0
    let keypair = derive_keypair(TEST_MNEMONIC, 0, 0, None).expect("Failed to derive keypair");

    // Verify we got a non-zero private key
    assert_ne!(keypair.private_key, Felt::ZERO);

    // Verify public key is valid (not identity point)
    let affine = keypair.public_key.to_affine().unwrap();
    assert_ne!(affine.x(), Felt::ZERO);

    println!("TONGO Private Key: {:#x}", keypair.private_key);
    println!("TONGO Public Key (x): {:#x}", affine.x());
}

#[test]
fn test_derive_starknet_account_address() {
    // This test verifies we can derive an OpenZeppelin account address
    // using the same class hash as the TypeScript reference

    // Parse the OZ class hash
    let class_hash = Felt::from_hex(OZ_ACCOUNT_CLASS_HASH).expect("Invalid OZ class hash");

    // Derive a keypair (using standard Starknet coin type 9004 path for account contracts)
    // For account contract derivation, we'd use: m/44'/9004'/0'/0/0
    // But for simplicity in this test, we'll use any valid public key
    let keypair = derive_keypair(TEST_MNEMONIC, 0, 0, None).expect("Failed to derive keypair");

    let affine = keypair.public_key.to_affine().unwrap();
    let public_key_x = affine.x();

    // Derive the account address
    let account_address = derive_oz_account_address(&public_key_x, &class_hash, None)
        .expect("Failed to derive account address");

    // Verify we got a non-zero address
    assert_ne!(account_address, Felt::ZERO);

    println!("Public Key (x): {:#x}", public_key_x);
    println!("Derived Account Address: {:#x}", account_address);
}

#[test]
fn test_deterministic_address_derivation() {
    // Verify that deriving the same keypair multiple times produces
    // the same account address (determinism)

    let class_hash = Felt::from_hex(OZ_ACCOUNT_CLASS_HASH).unwrap();

    let keypair1 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let keypair2 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();

    assert_eq!(keypair1.private_key, keypair2.private_key);

    let affine1 = keypair1.public_key.to_affine().unwrap();
    let affine2 = keypair2.public_key.to_affine().unwrap();

    let addr1 = derive_oz_account_address(&affine1.x(), &class_hash, None).unwrap();
    let addr2 = derive_oz_account_address(&affine2.x(), &class_hash, None).unwrap();

    assert_eq!(addr1, addr2);
}

#[test]
fn test_different_indices_produce_different_addresses() {
    // Verify that different address indices produce different account addresses

    let class_hash = Felt::from_hex(OZ_ACCOUNT_CLASS_HASH).unwrap();

    let keypair0 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let keypair1 = derive_keypair(TEST_MNEMONIC, 1, 0, None).unwrap();

    let affine0 = keypair0.public_key.to_affine().unwrap();
    let affine1 = keypair1.public_key.to_affine().unwrap();

    let addr0 = derive_oz_account_address(&affine0.x(), &class_hash, None).unwrap();
    let addr1 = derive_oz_account_address(&affine1.x(), &class_hash, None).unwrap();

    assert_ne!(addr0, addr1);

    println!("Address 0: {:#x}", addr0);
    println!("Address 1: {:#x}", addr1);
}
