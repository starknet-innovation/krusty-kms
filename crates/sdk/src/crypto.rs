//! Cryptographic utilities for TONGO SDK.
//!
//! This module provides:
//! - ECDH shared secret derivation on the Stark curve
//! - XChaCha20-Poly1305 authenticated encryption for audit hints

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use krusty_kms_common::{KmsError, Result};
use sha2::{Digest, Sha256};
use krusty_kms_crypto::StarkCurve;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Size of the XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_SIZE: usize = 24;

/// Size of the Poly1305 authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Derives a shared secret using ECDH on the Stark curve.
///
/// Computes: shared_point = other_public_key * my_private_key
/// Then hashes the x-coordinate to produce a 32-byte key.
///
/// # Arguments
/// * `my_private_key` - The local private key scalar
/// * `other_public_key` - The other party's public key point
///
/// # Returns
/// A 32-byte shared secret suitable for symmetric encryption
pub fn derive_shared_secret(
    my_private_key: &Felt,
    other_public_key: &ProjectivePoint,
) -> Result<[u8; 32]> {
    // Compute shared point: P = other_public_key * my_private_key
    let shared_point = StarkCurve::mul(my_private_key, Some(other_public_key));

    // Get the x-coordinate of the shared point
    let affine = shared_point
        .to_affine()
        .map_err(|_| KmsError::PointAtInfinity)?;

    // Hash the x-coordinate to derive the symmetric key
    // This provides domain separation and ensures uniform distribution
    let mut hasher = Sha256::new();
    hasher.update(b"TONGO_AUDIT_KEY_V1");
    hasher.update(affine.x().to_bytes_be());

    let hash_result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_result);

    Ok(key)
}

/// Encrypts a u128 balance value using XChaCha20-Poly1305.
///
/// # Arguments
/// * `plaintext_balance` - The balance value to encrypt
/// * `shared_secret` - 32-byte key derived from ECDH
///
/// # Returns
/// A tuple of (ciphertext, nonce) where:
/// - ciphertext is 64 bytes (16 bytes plaintext + 16 bytes tag, padded to 64)
/// - nonce is 24 bytes
pub fn encrypt_audit_hint(
    plaintext_balance: u128,
    shared_secret: &[u8; 32],
) -> Result<([u8; 64], [u8; 24])> {
    // Generate a random 24-byte nonce
    let mut nonce_bytes = [0u8; 24];
    krusty_kms_crypto::fill_random_bytes(&mut nonce_bytes);

    // Create the cipher
    let cipher = XChaCha20Poly1305::new_from_slice(shared_secret)
        .map_err(|e| KmsError::CryptoError(format!("Invalid key: {}", e)))?;

    let nonce = XNonce::from_slice(&nonce_bytes);

    // Encrypt the balance (as 16-byte big-endian)
    let plaintext = plaintext_balance.to_be_bytes();
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| KmsError::CryptoError(format!("Encryption failed: {}", e)))?;

    // Pack into 64-byte output (ciphertext + tag = 32 bytes, padded)
    let mut ct_out = [0u8; 64];
    let copy_len = ciphertext.len().min(64);
    ct_out[..copy_len].copy_from_slice(&ciphertext[..copy_len]);

    Ok((ct_out, nonce_bytes))
}

/// Decrypts an audit hint ciphertext to recover the balance.
///
/// # Arguments
/// * `ciphertext` - 64-byte ciphertext (only first 32 bytes used)
/// * `nonce` - 24-byte nonce
/// * `shared_secret` - 32-byte key derived from ECDH
///
/// # Returns
/// The decrypted u128 balance value
pub fn decrypt_audit_hint(
    ciphertext: &[u8; 64],
    nonce: &[u8; 24],
    shared_secret: &[u8; 32],
) -> Result<u128> {
    let cipher = XChaCha20Poly1305::new_from_slice(shared_secret)
        .map_err(|e| KmsError::CryptoError(format!("Invalid key: {}", e)))?;

    let nonce = XNonce::from_slice(nonce);

    // The actual ciphertext is 16 bytes plaintext + 16 bytes tag = 32 bytes
    let ct_len = 16 + TAG_SIZE; // 32 bytes
    let plaintext = cipher
        .decrypt(nonce, &ciphertext[..ct_len])
        .map_err(|e| KmsError::CryptoError(format!("Decryption failed: {}", e)))?;

    // Convert back to u128
    if plaintext.len() != 16 {
        return Err(KmsError::CryptoError(format!(
            "Invalid plaintext length: expected 16, got {}",
            plaintext.len()
        )));
    }

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&plaintext);
    Ok(u128::from_be_bytes(bytes))
}

/// Encrypts an audit hint for a specific auditor.
///
/// This is a convenience function that:
/// 1. Derives the shared secret from user's private key and auditor's public key
/// 2. Encrypts the balance using XChaCha20-Poly1305
///
/// # Arguments
/// * `balance` - The plaintext balance to encrypt
/// * `user_private_key` - The user's private key
/// * `auditor_public_key` - The auditor's public key
///
/// # Returns
/// A tuple of (ciphertext, nonce)
pub fn encrypt_for_auditor(
    balance: u128,
    user_private_key: &Felt,
    auditor_public_key: &ProjectivePoint,
) -> Result<([u8; 64], [u8; 24])> {
    let shared_secret = derive_shared_secret(user_private_key, auditor_public_key)?;
    encrypt_audit_hint(balance, &shared_secret)
}

/// Decrypts an audit hint as the auditor.
///
/// # Arguments
/// * `ciphertext` - The encrypted balance
/// * `nonce` - The encryption nonce
/// * `auditor_private_key` - The auditor's private key
/// * `user_public_key` - The user's public key
///
/// # Returns
/// The decrypted balance
pub fn decrypt_as_auditor(
    ciphertext: &[u8; 64],
    nonce: &[u8; 24],
    auditor_private_key: &Felt,
    user_public_key: &ProjectivePoint,
) -> Result<u128> {
    let shared_secret = derive_shared_secret(auditor_private_key, user_public_key)?;
    decrypt_audit_hint(ciphertext, nonce, &shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let balance: u128 = 1_000_000_000_000_000_000; // 1 STRK in FRI

        // Generate test keypairs
        let user_sk = Felt::from(42u64);
        let user_pk = StarkCurve::mul_generator(&user_sk);

        let auditor_sk = Felt::from(123u64);
        let auditor_pk = StarkCurve::mul_generator(&auditor_sk);

        // User encrypts for auditor
        let (ciphertext, nonce) = encrypt_for_auditor(balance, &user_sk, &auditor_pk).unwrap();

        // Auditor decrypts
        let decrypted = decrypt_as_auditor(&ciphertext, &nonce, &auditor_sk, &user_pk).unwrap();

        assert_eq!(balance, decrypted);
    }

    #[test]
    fn test_zero_balance() {
        let balance: u128 = 0;

        let user_sk = Felt::from(42u64);
        let auditor_sk = Felt::from(123u64);
        let auditor_pk = StarkCurve::mul_generator(&auditor_sk);
        let user_pk = StarkCurve::mul_generator(&user_sk);

        let (ciphertext, nonce) = encrypt_for_auditor(balance, &user_sk, &auditor_pk).unwrap();
        let decrypted = decrypt_as_auditor(&ciphertext, &nonce, &auditor_sk, &user_pk).unwrap();

        assert_eq!(balance, decrypted);
    }

    #[test]
    fn test_max_balance() {
        let balance: u128 = u128::MAX;

        let user_sk = Felt::from(42u64);
        let auditor_sk = Felt::from(123u64);
        let auditor_pk = StarkCurve::mul_generator(&auditor_sk);
        let user_pk = StarkCurve::mul_generator(&user_sk);

        let (ciphertext, nonce) = encrypt_for_auditor(balance, &user_sk, &auditor_pk).unwrap();
        let decrypted = decrypt_as_auditor(&ciphertext, &nonce, &auditor_sk, &user_pk).unwrap();

        assert_eq!(balance, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let balance: u128 = 1000;

        let user_sk = Felt::from(42u64);
        let auditor_sk = Felt::from(123u64);
        let wrong_sk = Felt::from(999u64);
        let auditor_pk = StarkCurve::mul_generator(&auditor_sk);
        let user_pk = StarkCurve::mul_generator(&user_sk);

        let (ciphertext, nonce) = encrypt_for_auditor(balance, &user_sk, &auditor_pk).unwrap();

        // Try to decrypt with wrong key
        let result = decrypt_as_auditor(&ciphertext, &nonce, &wrong_sk, &user_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_shared_secret_symmetry() {
        // ECDH should produce the same shared secret from both sides
        let alice_sk = Felt::from(42u64);
        let alice_pk = StarkCurve::mul_generator(&alice_sk);

        let bob_sk = Felt::from(123u64);
        let bob_pk = StarkCurve::mul_generator(&bob_sk);

        let secret_from_alice = derive_shared_secret(&alice_sk, &bob_pk).unwrap();
        let secret_from_bob = derive_shared_secret(&bob_sk, &alice_pk).unwrap();

        assert_eq!(secret_from_alice, secret_from_bob);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let balance: u128 = 1000;

        let user_sk = Felt::from(42u64);
        let auditor_sk = Felt::from(123u64);
        let auditor_pk = StarkCurve::mul_generator(&auditor_sk);
        let user_pk = StarkCurve::mul_generator(&user_sk);

        let (mut ciphertext, nonce) = encrypt_for_auditor(balance, &user_sk, &auditor_pk).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        let result = decrypt_as_auditor(&ciphertext, &nonce, &auditor_sk, &user_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let balance: u128 = 1000;

        let user_sk = Felt::from(42u64);
        let auditor_sk = Felt::from(123u64);
        let auditor_pk = StarkCurve::mul_generator(&auditor_sk);
        let user_pk = StarkCurve::mul_generator(&user_sk);

        let (ciphertext, mut nonce) = encrypt_for_auditor(balance, &user_sk, &auditor_pk).unwrap();

        // Use wrong nonce
        nonce[0] ^= 0xFF;

        let result = decrypt_as_auditor(&ciphertext, &nonce, &auditor_sk, &user_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_direct_encrypt_decrypt() {
        let balance: u128 = 999_999_999;

        let user_sk = Felt::from(42u64);
        let auditor_sk = Felt::from(123u64);
        let auditor_pk = StarkCurve::mul_generator(&auditor_sk);

        let shared_secret = derive_shared_secret(&user_sk, &auditor_pk).unwrap();

        let (ciphertext, nonce) = encrypt_audit_hint(balance, &shared_secret).unwrap();
        let decrypted = decrypt_audit_hint(&ciphertext, &nonce, &shared_secret).unwrap();

        assert_eq!(balance, decrypted);
    }

    #[test]
    fn test_different_balances_produce_different_ciphertext() {
        let balance1: u128 = 1000;
        let balance2: u128 = 2000;

        let user_sk = Felt::from(42u64);
        let auditor_sk = Felt::from(123u64);
        let auditor_pk = StarkCurve::mul_generator(&auditor_sk);

        let shared_secret = derive_shared_secret(&user_sk, &auditor_pk).unwrap();

        let (ciphertext1, _) = encrypt_audit_hint(balance1, &shared_secret).unwrap();
        let (ciphertext2, _) = encrypt_audit_hint(balance2, &shared_secret).unwrap();

        // Ciphertexts should be different (also due to random nonces)
        assert_ne!(ciphertext1, ciphertext2);
    }
}
