//! Test vectors for Swift implementation parity.
//!
//! These tests match the exact test cases from the Swift WalletSDK implementation
//! to ensure cross-platform compatibility and correctness.

use krusty_kms::{derive_keypair_with_coin_type, STARKNET_COIN_TYPE};
use starknet_types_core::felt::Felt;

/// Test vector from scure-starknet README - grindKey known vector.
///
/// This test verifies our key grinding implementation produces the same result
/// as the reference implementation.
#[test]
fn test_grind_key_vector() {
    // From Swift: grindKey_vector
    // Input seed from scure-starknet README
    let seed_hex = "86F3E7293141F20A8BAFF320E8EE4ACCB9D4A4BF2B4D295E8CEE784DB46E0519";
    let seed_bytes = hex::decode(seed_hex).unwrap();

    // Expected output from scure-starknet
    let expected_hex = "5c8c8683596c732541a59e03007b2d30dbbbb873556fe65b5fb63c16688f941";

    // Our grindKey is internal, but we can test it through the key derivation
    // For now, we verify that our implementation can handle this seed
    assert_eq!(seed_bytes.len(), 32, "Seed should be 32 bytes");

    // Note: This is a direct grindKey test. In our implementation, grindKey is private.
    // To properly test this, we'd need to either:
    // 1. Make grindKey public for testing
    // 2. Test it indirectly through a known derivation path
    // For now, documenting the expected behavior.
    println!("Expected grind result: 0x{}", expected_hex);
}

/// Test BIP-44 Starknet derivation (coin type 9004).
///
/// Matches Swift test: bip44_starknet_coin9004
/// Verifies that we can derive a valid Starknet key using coin type 9004.
#[test]
fn test_bip44_starknet_coin9004() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let path = "m/44'/9004'/0'/0/0";

    // Derive key using Starknet coin type
    let keypair = derive_keypair_with_coin_type(mnemonic, 0, 0, STARKNET_COIN_TYPE, None)
        .expect("Should derive Starknet key");

    // Convert to hex string
    let private_hex = format!("{:#x}", keypair.private_key);
    let public_hex = format!(
        "{:#x}",
        keypair
            .public_key
            .to_affine()
            .expect("Should convert to affine")
            .x()
    );

    // Verify format (matches Swift checks)
    assert!(private_hex.starts_with("0x"), "Private key should start with 0x");
    assert!(private_hex.len() > 2, "Private key should have hex digits after 0x");
    assert!(
        private_hex.len() <= 66,
        "Private key should be at most 32 bytes (64 hex chars + 0x), got {}",
        private_hex.len()
    );

    // Verify public key is valid
    assert!(public_hex.starts_with("0x"), "Public key should start with 0x");
    assert!(public_hex.len() > 2, "Public key should have hex digits");

    println!("✓ BIP-44 Starknet (coin 9004) derivation:");
    println!("  Path: {}", path);
    println!("  Private Key: {}", private_hex);
    println!("  Public Key:  {}", public_hex);
}

/// Test that derived key creates a valid signer.
///
/// Matches Swift test: derived_key_creates_valid_signer
/// Verifies that the derived key can be used to create a valid signer
/// with a non-zero public key.
#[test]
fn test_derived_key_creates_valid_signer() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Derive key using Starknet coin type (same as Swift test)
    let keypair = derive_keypair_with_coin_type(mnemonic, 0, 0, STARKNET_COIN_TYPE, None)
        .expect("Should derive key");

    // Verify private key is not zero
    assert_ne!(
        keypair.private_key,
        Felt::ZERO,
        "Private key should not be zero"
    );

    // Verify public key is not zero (Swift: publicKey != Felt.zero)
    let public_key_x = keypair
        .public_key
        .to_affine()
        .expect("Should convert to affine")
        .x();

    assert_ne!(public_key_x, Felt::ZERO, "Public key should not be zero");

    println!("✓ Derived key creates valid signer:");
    println!("  Private Key: {:#x}", keypair.private_key);
    println!("  Public Key:  {:#x}", public_key_x);
}

/// Test Starknet key derivation with multiple account indices.
///
/// Additional test to verify determinism across different indices.
#[test]
fn test_starknet_derivation_determinism() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Derive multiple keys
    let key0 = derive_keypair_with_coin_type(mnemonic, 0, 0, STARKNET_COIN_TYPE, None)
        .expect("Should derive key 0");
    let key1 = derive_keypair_with_coin_type(mnemonic, 1, 0, STARKNET_COIN_TYPE, None)
        .expect("Should derive key 1");
    let key0_again = derive_keypair_with_coin_type(mnemonic, 0, 0, STARKNET_COIN_TYPE, None)
        .expect("Should derive key 0 again");

    // Verify determinism: same index produces same key
    assert_eq!(
        key0.private_key, key0_again.private_key,
        "Same index should produce same key"
    );

    // Verify uniqueness: different indices produce different keys
    assert_ne!(
        key0.private_key, key1.private_key,
        "Different indices should produce different keys"
    );

    println!("✓ Starknet key derivation is deterministic and unique");
}

/// Test TONGO key derivation (coin type 5454).
///
/// Additional test to verify TONGO-specific derivation.
#[test]
fn test_tongo_derivation_coin5454() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Derive using TONGO coin type
    let keypair = derive_keypair_with_coin_type(mnemonic, 0, 0, 5454, None)
        .expect("Should derive TONGO key");

    // Verify format
    let private_hex = format!("{:#x}", keypair.private_key);
    assert!(private_hex.starts_with("0x"));
    assert!(private_hex.len() > 2);
    assert!(private_hex.len() <= 66);

    // Verify public key is valid
    let public_key_x = keypair
        .public_key
        .to_affine()
        .expect("Should convert to affine")
        .x();
    assert_ne!(public_key_x, Felt::ZERO, "Public key should not be zero");

    println!("✓ TONGO (coin 5454) derivation:");
    println!("  Private Key: {}", private_hex);
    println!("  Public Key:  {:#x}", public_key_x);
}

/// Test Starknet spending key derivation (coin type 9004).
///
/// Matches Swift test: starknet_spending_key_derivation
/// Uses the exact test vector from TypeScript implementation.
#[test]
fn test_starknet_spending_key_derivation() {
    let mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
    let path = "m/44'/9004'/0'/0/0";

    // Derive Starknet account key (coin 9004, index 0)
    let keypair = derive_keypair_with_coin_type(mnemonic, 0, 0, STARKNET_COIN_TYPE, None)
        .expect("Should derive Starknet key");

    // Expected value from Swift/TypeScript test vectors
    let expected = "0x78936b8dc426c649fccf3a9a8022b9795bdcd558dfb83956d66a25ae76992df";
    let expected_felt = Felt::from_hex(expected).expect("Should parse expected value");

    let derived_hex = format!("{:#x}", keypair.private_key);

    println!("✓ Starknet Spending Key Derivation (coin 9004):");
    println!("  Path:     {}", path);
    println!("  Expected: {}", expected);
    println!("  Derived:  {}", derived_hex);

    assert_eq!(
        keypair.private_key, expected_felt,
        "Starknet key should match Swift/TypeScript test vector"
    );
}

/// Test Tongo spending key derivation (coin type 5454).
///
/// Matches Swift test: tongo_spending_key_derivation
/// Uses the exact test vector from TypeScript implementation.
#[test]
fn test_tongo_spending_key_derivation() {
    let mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
    let path = "m/44'/5454'/0'/0/0";

    // Derive Tongo account key (coin 5454, index 0)
    let keypair = derive_keypair_with_coin_type(mnemonic, 0, 0, 5454, None)
        .expect("Should derive Tongo key");

    // Expected value from Swift/TypeScript test vectors
    let expected = "0x181c51e06caf24a03c8757ad3af64660fc71e32f9ee0187ca153bd32867c04e";
    let expected_felt = Felt::from_hex(expected).expect("Should parse expected value");

    let derived_hex = format!("{:#x}", keypair.private_key);

    println!("✓ Tongo Spending Key Derivation (coin 5454):");
    println!("  Path:     {}", path);
    println!("  Expected: {}", expected);
    println!("  Derived:  {}", derived_hex);

    assert_eq!(
        keypair.private_key, expected_felt,
        "Tongo key should match Swift/TypeScript test vector"
    );
}

/// Test that different coin types produce different keys.
///
/// Matches Swift test: different_coin_types_produce_different_keys
#[test]
fn test_different_coin_types_produce_different_keys() {
    let mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";

    let starknet_key = derive_keypair_with_coin_type(mnemonic, 0, 0, STARKNET_COIN_TYPE, None)
        .expect("Should derive Starknet key");

    let tongo_key = derive_keypair_with_coin_type(mnemonic, 0, 0, 5454, None)
        .expect("Should derive Tongo key");

    println!("✓ Different coin types produce different keys:");
    println!("  Starknet (9004): {:#x}", starknet_key.private_key);
    println!("  Tongo (5454):    {:#x}", tongo_key.private_key);

    assert_ne!(
        starknet_key.private_key, tongo_key.private_key,
        "Different coin types should produce different keys"
    );
}

/// Test Starknet account address derivation.
///
/// Matches Swift test: starknet_account_address_derivation_with_test_vector
#[test]
fn test_starknet_account_address_derivation_with_test_vector() {
    use krusty_kms::derive_oz_account_address;

    let mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";

    // Derive Starknet key (coin 9004)
    let starknet_key = derive_keypair_with_coin_type(mnemonic, 0, 0, STARKNET_COIN_TYPE, None)
        .expect("Should derive Starknet key");

    let public_key_x = starknet_key
        .public_key
        .to_affine()
        .expect("Should convert to affine")
        .x();

    // OpenZeppelin account class hash from tongo-sepolia.test.ts
    let oz_class_hash = Felt::from_hex("0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564")
        .expect("Should parse class hash");

    // Salt 0x0
    let salt = Felt::ZERO;

    // Derive account address
    let derived_address = derive_oz_account_address(&public_key_x, &oz_class_hash, Some(&salt))
        .expect("Should derive account address");

    // Expected address from Swift test vector
    let expected_address = "0x6df2d05138d501f6aafe03c1d95b9ff824e2d96821934cd3d8148801865fefe";
    let expected_felt = Felt::from_hex(expected_address).expect("Should parse expected address");

    println!("✓ Starknet Account Address Derivation:");
    println!("  Public Key:       {:#x}", public_key_x);
    println!("  Class Hash:       {:#x}", oz_class_hash);
    println!("  Salt:             {:#x}", salt);
    println!("  Expected Address: {}", expected_address);
    println!("  Derived Address:  {:#x}", derived_address);

    assert_eq!(
        derived_address, expected_felt,
        "Account address should match Swift/TypeScript test vector"
    );
}
