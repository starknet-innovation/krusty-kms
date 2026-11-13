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
use zeroize::Zeroizing;

mod scrypt_limits;
pub use scrypt_limits::DEFAULT_SCRYPT_N_MAX;
pub(crate) use scrypt_limits::{
    derive_scrypt_key, ensure_default_scrypt_budget, scrypt_log_n, SCRYPT_MEMORY_CEILING_BYTES,
};

/// XChaCha20-Poly1305 extended nonce length, in bytes.
pub(crate) const XNONCE_LEN: usize = 24;
/// Keep direct ciphertexts within the WASM decryption input ceiling.
const MAX_DIRECT_KEY_BYTES: usize = 1024 * 1024 - 16;

/// Validate a nonce length before it reaches the AEAD.
///
/// A malformed nonce from untrusted JSON must return an error rather than panic.
/// `TryFrom` performs the length check without asserting, preserving the existing
/// deserialization error at this untrusted boundary.
///
/// `DeserializationError` rather than `CryptoError`: the length is a property of the
/// stored file, not of the password, and the two are the same variant to a caller who
/// only sees the error code. `CryptoError` maps to `CRYPTO_ERROR` in the wasm layer,
/// which reads as "wrong password" and invites a retry that cannot succeed.
pub(crate) fn xnonce(nonce: &[u8]) -> Result<&XNonce> {
    <&XNonce>::try_from(nonce).map_err(|_| {
        KmsError::DeserializationError(format!(
            "Invalid nonce length: expected {XNONCE_LEN} bytes, got {}",
            nonce.len()
        ))
    })
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
    ensure_default_scrypt_budget(scrypt_n)?;
    let hex_str = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(private_key_hex);
    if hex_str.len() > MAX_DIRECT_KEY_BYTES * 2 {
        return Err(KmsError::CryptoError(format!(
            "private key exceeds the {MAX_DIRECT_KEY_BYTES} byte limit"
        )));
    }
    // Generate 16-byte salt
    let salt = krusty_kms_crypto::random_bytes::<16>();

    // Derive encryption key
    let key = derive_scrypt_key(password.as_bytes(), &salt, scrypt_n)?;

    // Generate 24-byte nonce
    let nonce_bytes = krusty_kms_crypto::random_bytes::<XNONCE_LEN>();

    // Decode hex private key; scrubbed on drop — this buffer is the raw key.
    let plaintext = Zeroizing::new(
        hex::decode(hex_str).map_err(|e| KmsError::CryptoError(format!("Invalid hex: {e}")))?,
    );

    // Encrypt
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|e| KmsError::CryptoError(format!("Invalid key: {e}")))?;
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
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
///
/// The legacy N range is for deliberate recovery by a trusted Rust caller.
/// Use [`decrypt_private_key_bounded`] for untrusted metadata.
pub fn decrypt_private_key(
    encrypted: &EncryptedKey,
    password: &str,
    scrypt_n: u32,
) -> Result<String> {
    scrypt_limits::ensure_direct_input_lengths(encrypted)?;
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

/// Decrypt a private key using the default 256 MiB KDF memory budget.
///
/// Prefer this when `scrypt_n` comes from untrusted metadata. The legacy
/// [`decrypt_private_key`] accepts up to `N=2^20` so older high-cost keys remain
/// recoverable when the caller deliberately opts into their resource cost.
pub fn decrypt_private_key_bounded(
    encrypted: &EncryptedKey,
    password: &str,
    scrypt_n: u32,
) -> Result<String> {
    ensure_default_scrypt_budget(scrypt_n)?;
    decrypt_private_key(encrypted, password, scrypt_n)
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
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
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
mod tests;
