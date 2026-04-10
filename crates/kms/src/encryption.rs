//! Private key and payload encryption using XChaCha20-Poly1305 with scrypt KDF.
//!
//! This module provides:
//! - Password-based encryption/decryption of private keys (scrypt + XChaCha20-Poly1305)
//! - Direct key-based encryption/decryption for arbitrary payloads

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use krusty_kms_common::{KmsError, Result};
use scrypt::{scrypt, Params as ScryptParams};
use zeroize::Zeroize;

/// Encrypted private key with KDF salt.
#[derive(Debug, Clone)]
pub struct EncryptedKey {
    /// 24-byte XChaCha20 nonce.
    pub nonce: Vec<u8>,
    /// 16-byte scrypt salt.
    pub salt: Vec<u8>,
    /// Ciphertext with 16-byte Poly1305 authentication tag appended.
    pub encrypted_key: Vec<u8>,
}

/// Encrypted payload (no KDF metadata -- caller provides key directly).
#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    /// 24-byte XChaCha20 nonce.
    pub nonce: Vec<u8>,
    /// Ciphertext with 16-byte Poly1305 authentication tag appended.
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from a password and salt using scrypt.
fn derive_scrypt_key(password: &[u8], salt: &[u8], n: u32) -> Result<[u8; 32]> {
    let log_n = (n as f64).log2() as u8;
    let params = ScryptParams::new(log_n, 8, 1, 32)
        .map_err(|e| KmsError::CryptoError(format!("Invalid scrypt params: {e}")))?;
    let mut key = [0u8; 32];
    scrypt(password, salt, &params, &mut key)
        .map_err(|e| KmsError::CryptoError(format!("Scrypt KDF failed: {e}")))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Password-based private key encryption
// ---------------------------------------------------------------------------

/// Encrypt a hex-encoded private key with a password using scrypt + XChaCha20-Poly1305.
///
/// # Arguments
/// * `private_key_hex` - Hex-encoded private key (with or without `0x` prefix)
/// * `password` - User-supplied password
/// * `scrypt_n` - Scrypt cost parameter N (must be a power of 2, e.g. 32768)
///
/// # Returns
/// An [`EncryptedKey`] containing the nonce, salt, and ciphertext.
pub fn encrypt_private_key(
    private_key_hex: &str,
    password: &str,
    scrypt_n: u32,
) -> Result<EncryptedKey> {
    // Generate 16-byte salt
    let mut salt = [0u8; 16];
    krusty_kms_crypto::fill_random_bytes(&mut salt);

    // Derive encryption key
    let mut key = derive_scrypt_key(password.as_bytes(), &salt, scrypt_n)?;

    // Generate 24-byte nonce
    let mut nonce_bytes = [0u8; 24];
    krusty_kms_crypto::fill_random_bytes(&mut nonce_bytes);

    // Decode hex private key
    let hex_str = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(private_key_hex);
    let plaintext =
        hex::decode(hex_str).map_err(|e| KmsError::CryptoError(format!("Invalid hex: {e}")))?;

    // Encrypt
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| KmsError::CryptoError(format!("Invalid key: {e}")))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| KmsError::CryptoError(format!("Encryption failed: {e}")))?;

    // Zeroize the derived key
    key.zeroize();

    Ok(EncryptedKey {
        nonce: nonce_bytes.to_vec(),
        salt: salt.to_vec(),
        encrypted_key: ciphertext,
    })
}

/// Decrypt a private key that was encrypted with [`encrypt_private_key`].
///
/// # Arguments
/// * `encrypted` - The encrypted key bundle
/// * `password` - The password used during encryption
/// * `scrypt_n` - The same scrypt cost parameter used during encryption
///
/// # Returns
/// Hex-encoded private key (no `0x` prefix).
pub fn decrypt_private_key(
    encrypted: &EncryptedKey,
    password: &str,
    scrypt_n: u32,
) -> Result<String> {
    // Derive key from password + salt
    let mut key = derive_scrypt_key(password.as_bytes(), &encrypted.salt, scrypt_n)?;

    // Decrypt
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| KmsError::CryptoError(format!("Invalid key: {e}")))?;
    let nonce = XNonce::from_slice(&encrypted.nonce);
    let plaintext = cipher
        .decrypt(nonce, encrypted.encrypted_key.as_ref())
        .map_err(|e| KmsError::CryptoError(format!("Decryption failed: {e}")))?;

    // Zeroize the derived key
    key.zeroize();

    Ok(hex::encode(plaintext))
}

// ---------------------------------------------------------------------------
// Direct key-based encryption
// ---------------------------------------------------------------------------

/// Encrypt arbitrary data with a pre-derived 32-byte key.
///
/// # Arguments
/// * `plaintext` - Raw bytes to encrypt
/// * `key` - 32-byte symmetric key
///
/// # Returns
/// An [`EncryptedPayload`] containing the nonce and ciphertext.
pub fn encrypt_with_key(plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedPayload> {
    let mut nonce_bytes = [0u8; 24];
    krusty_kms_crypto::fill_random_bytes(&mut nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| KmsError::CryptoError(format!("Invalid key: {e}")))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| KmsError::CryptoError(format!("Encryption failed: {e}")))?;

    Ok(EncryptedPayload {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt data that was encrypted with [`encrypt_with_key`].
///
/// # Arguments
/// * `payload` - The encrypted payload
/// * `key` - The same 32-byte symmetric key used during encryption
///
/// # Returns
/// The decrypted plaintext bytes.
pub fn decrypt_with_key(payload: &EncryptedPayload, key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| KmsError::CryptoError(format!("Invalid key: {e}")))?;
    let nonce = XNonce::from_slice(&payload.nonce);
    cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|e| KmsError::CryptoError(format!("Decryption failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use a low scrypt N for fast tests
    const TEST_SCRYPT_N: u32 = 1024;

    #[test]
    fn encrypt_decrypt_private_key_roundtrip() {
        let private_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let password = "hunter2";

        let encrypted = encrypt_private_key(private_key, password, TEST_SCRYPT_N).unwrap();
        assert_eq!(encrypted.nonce.len(), 24);
        assert_eq!(encrypted.salt.len(), 16);

        let decrypted = decrypt_private_key(&encrypted, password, TEST_SCRYPT_N).unwrap();
        assert_eq!(decrypted, private_key);
    }

    #[test]
    fn encrypt_decrypt_private_key_with_0x_prefix() {
        let private_key = "0xdeadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233";
        let password = "test";

        let encrypted = encrypt_private_key(private_key, password, TEST_SCRYPT_N).unwrap();
        let decrypted = decrypt_private_key(&encrypted, password, TEST_SCRYPT_N).unwrap();
        // Decrypted is returned without 0x prefix
        assert_eq!(
            decrypted,
            "deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233"
        );
    }

    #[test]
    fn wrong_password_fails_decryption() {
        let private_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let password = "correct-password";

        let encrypted = encrypt_private_key(private_key, password, TEST_SCRYPT_N).unwrap();

        let result = decrypt_private_key(&encrypted, "wrong-password", TEST_SCRYPT_N);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_with_key_roundtrip() {
        let plaintext = b"some secret data that must remain confidential";
        let key: [u8; 32] = [42u8; 32];

        let payload = encrypt_with_key(plaintext, &key).unwrap();
        assert_eq!(payload.nonce.len(), 24);

        let decrypted = decrypt_with_key(&payload, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt_with_key() {
        let plaintext = b"secret";
        let key: [u8; 32] = [1u8; 32];
        let wrong_key: [u8; 32] = [2u8; 32];

        let payload = encrypt_with_key(plaintext, &key).unwrap();

        let result = decrypt_with_key(&payload, &wrong_key);
        assert!(result.is_err());
    }
}
