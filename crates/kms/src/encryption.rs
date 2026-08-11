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
use zeroize::Zeroizing;

/// XChaCha20-Poly1305 extended nonce length, in bytes.
pub(crate) const XNONCE_LEN: usize = 24;

/// Validate a nonce length before it reaches the AEAD.
///
/// `XNonce::from_slice` asserts on a mismatch rather than erroring, so a nonce taken
/// from untrusted JSON aborted the process instead of returning.
///
/// `DeserializationError` rather than `CryptoError`: the length is a property of the
/// stored file, not of the password, and the two are the same variant to a caller who
/// only sees the error code. `CryptoError` maps to `CRYPTO_ERROR` in the wasm layer,
/// which reads as "wrong password" and invites a retry that cannot succeed.
pub(crate) fn xnonce(nonce: &[u8]) -> Result<&XNonce> {
    if nonce.len() != XNONCE_LEN {
        return Err(KmsError::DeserializationError(format!(
            "Invalid nonce length: expected {XNONCE_LEN} bytes, got {}",
            nonce.len()
        )));
    }
    Ok(XNonce::from_slice(nonce))
}

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

/// Minimum allowed scrypt N (2^10).
pub(crate) const SCRYPT_N_MIN: u32 = 1 << 10;
/// Maximum allowed scrypt N (2^20).
pub(crate) const SCRYPT_N_MAX: u32 = 1 << 20;

/// Validate scrypt N and return `log2(N)` for [`ScryptParams`].
///
/// Requires `N` to be a power of two in `[2^10, 2^20]`.
pub(crate) fn scrypt_log_n(n: u32) -> Result<u8> {
    if !(SCRYPT_N_MIN..=SCRYPT_N_MAX).contains(&n) || !n.is_power_of_two() {
        return Err(KmsError::CryptoError(format!(
            "Invalid scrypt N={n}: must be a power of 2 in [{SCRYPT_N_MIN}, {SCRYPT_N_MAX}]"
        )));
    }
    Ok(n.trailing_zeros() as u8)
}

/// Derive a 32-byte key from a password and salt using scrypt.
///
/// [`Zeroizing`] rather than a bare array: every caller has a `?` between the
/// derivation and the end of the function, and a wrong password takes that path.
pub(crate) fn derive_scrypt_key(
    password: &[u8],
    kdf_salt: &[u8],
    n: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let log_n = scrypt_log_n(n)?;
    let params = ScryptParams::new(log_n, 8, 1)
        .map_err(|e| KmsError::CryptoError(format!("Invalid scrypt params: {e}")))?;
    let mut key = Zeroizing::new([u8::default(); 32]);
    scrypt(password, kdf_salt, &params, &mut *key)
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
    let salt = krusty_kms_crypto::random_bytes::<16>();

    // Derive encryption key
    let key = derive_scrypt_key(password.as_bytes(), &salt, scrypt_n)?;

    // Generate 24-byte nonce
    let nonce_bytes = krusty_kms_crypto::random_bytes::<XNONCE_LEN>();

    // Decode hex private key; scrubbed on drop — this buffer is the raw key.
    let hex_str = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(private_key_hex);
    let plaintext = Zeroizing::new(
        hex::decode(hex_str).map_err(|e| KmsError::CryptoError(format!("Invalid hex: {e}")))?,
    );

    // Encrypt
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|e| KmsError::CryptoError(format!("Invalid key: {e}")))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| KmsError::CryptoError(format!("Encryption failed: {e}")))?;

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
    // Validate before deriving, so a malformed nonce costs no KDF work.
    let nonce = xnonce(&encrypted.nonce)?;

    let key = derive_scrypt_key(password.as_bytes(), &encrypted.salt, scrypt_n)?;

    // Decrypt
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|e| KmsError::CryptoError(format!("Invalid key: {e}")))?;
    // The decrypted private key, scrubbed on drop like the key that unwrapped it.
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, encrypted.encrypted_key.as_ref())
            .map_err(|e| KmsError::CryptoError(format!("Decryption failed: {e}")))?,
    );

    Ok(hex::encode(&*plaintext))
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
    let nonce_bytes = krusty_kms_crypto::random_bytes::<XNONCE_LEN>();

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
    let nonce = xnonce(&payload.nonce)?;
    cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|e| KmsError::CryptoError(format!("Decryption failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use a low scrypt N for fast tests
    const TEST_SCRYPT_N: u32 = 1024;

    // A nonce length must be validated, not asserted.

    #[test]
    fn decrypt_with_key_rejects_wrong_nonce_length_without_panicking() {
        // `XNonce::from_slice` asserts on a length mismatch, so a nonce taken
        // from untrusted JSON used to abort the process instead of erroring.
        let key = test_key(0);
        for len in [0usize, 4, 12, 23, 25, 64] {
            let payload = EncryptedPayload {
                nonce: vec![0u8; len],
                ciphertext: vec![0u8; 48],
            };
            let err = decrypt_with_key(&payload, &key).expect_err("must be rejected");
            assert!(
                format!("{err}").contains("Invalid nonce length"),
                "len={len}, got {err}"
            );
        }
    }

    #[test]
    fn decrypt_private_key_rejects_wrong_nonce_length_without_panicking() {
        for len in [0usize, 4, 12, 23, 25] {
            let encrypted = EncryptedKey {
                nonce: vec![0u8; len],
                salt: vec![0u8; 16],
                encrypted_key: vec![0u8; 48],
            };
            let err = decrypt_private_key(&encrypted, &test_password(0), TEST_SCRYPT_N)
                .expect_err("must be rejected");
            assert!(
                format!("{err}").contains("Invalid nonce length"),
                "len={len}, got {err}"
            );
        }
    }

    #[test]
    fn correct_nonce_length_is_accepted() {
        // Guards against over-tightening: a well-formed 24-byte nonce must
        // still reach the AEAD and fail on authentication, not on length.
        let payload = EncryptedPayload {
            nonce: vec![0u8; XNONCE_LEN],
            ciphertext: vec![0u8; 48],
        };
        let err = decrypt_with_key(&payload, &test_key(0)).expect_err("tag must fail");
        assert!(format!("{err}").contains("Decryption failed"), "got {err}");
    }

    fn test_password(offset: u8) -> String {
        (0..12)
            .map(|index| char::from(b'a' + index + offset))
            .collect()
    }

    fn test_key(offset: u8) -> [u8; 32] {
        std::array::from_fn(|index| index as u8 + offset)
    }

    #[test]
    fn encrypt_decrypt_private_key_roundtrip() {
        let private_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let password = test_password(0);

        let encrypted = encrypt_private_key(private_key, &password, TEST_SCRYPT_N).unwrap();
        assert_eq!(encrypted.nonce.len(), 24);
        assert_eq!(encrypted.salt.len(), 16);

        let decrypted = decrypt_private_key(&encrypted, &password, TEST_SCRYPT_N).unwrap();
        assert_eq!(decrypted, private_key);
    }

    #[test]
    fn encrypt_decrypt_private_key_with_0x_prefix() {
        let private_key = "0xdeadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233";
        let password = test_password(0);

        let encrypted = encrypt_private_key(private_key, &password, TEST_SCRYPT_N).unwrap();
        let decrypted = decrypt_private_key(&encrypted, &password, TEST_SCRYPT_N).unwrap();
        // Decrypted is returned without 0x prefix
        assert_eq!(
            decrypted,
            "deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233"
        );
    }

    #[test]
    fn wrong_password_fails_decryption() {
        let private_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let password = test_password(0);

        let encrypted = encrypt_private_key(private_key, &password, TEST_SCRYPT_N).unwrap();

        let wrong_password = test_password(1);
        let result = decrypt_private_key(&encrypted, &wrong_password, TEST_SCRYPT_N);
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_scrypt_n() {
        assert!(scrypt_log_n(1023).is_err());
        assert!(scrypt_log_n(3).is_err());
        assert!(scrypt_log_n(1 << 21).is_err());
        assert_eq!(scrypt_log_n(1024).unwrap(), 10);
    }

    #[test]
    fn encrypt_decrypt_with_key_roundtrip() {
        let plaintext = b"some secret data that must remain confidential";
        let key = test_key(0);

        let payload = encrypt_with_key(plaintext, &key).unwrap();
        assert_eq!(payload.nonce.len(), 24);

        let decrypted = decrypt_with_key(&payload, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt_with_key() {
        let plaintext = b"secret";
        let key = test_key(0);
        let wrong_key = test_key(1);

        let payload = encrypt_with_key(plaintext, &key).unwrap();

        let result = decrypt_with_key(&payload, &wrong_key);
        assert!(result.is_err());
    }
}
