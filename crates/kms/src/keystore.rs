//! Keystore encryption format and ethers.js keystore migration.
//!
//! This module provides:
//! - A krusty-kms native keystore format (version 1, XChaCha20-Poly1305 + scrypt)
//! - Decryption of ethers.js / Web3 Secret Storage keystores (version 3, AES-128-CTR + scrypt)

use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use krusty_kms_common::{KmsError, Result};
use scrypt::{scrypt, Params as ScryptParams};
use sha3::{Digest, Keccak256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::encryption::{decrypt_with_key, encrypt_with_key, scrypt_log_n};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

fn parse_u32_kdf_param(value: Option<u64>, field: &str) -> Result<u32> {
    let n = value
        .ok_or_else(|| KmsError::DeserializationError(format!("Missing kdfparams.{field}")))?;
    u32::try_from(n).map_err(|_| {
        KmsError::DeserializationError(format!("kdfparams.{field} exceeds u32 range (got {n})"))
    })
}

// ---------------------------------------------------------------------------
// Native keystore (version 1)
// ---------------------------------------------------------------------------

/// Encrypt a mnemonic into a JSON keystore string.
///
/// The resulting JSON has the form:
/// ```json
/// {
///   "version": 1,
///   "crypto": {
///     "cipher": "xchacha20-poly1305",
///     "kdf": "scrypt",
///     "kdfparams": { "n": 32768, "r": 8, "p": 1, "dklen": 32, "salt": "hex..." },
///     "nonce": "hex...",
///     "ciphertext": "hex..."
///   }
/// }
/// ```
///
/// # Arguments
/// * `mnemonic` - The mnemonic phrase to encrypt
/// * `password` - User-supplied password
/// * `scrypt_n` - Scrypt cost parameter N (must be a power of 2)
pub fn encrypt_keystore(mnemonic: &str, password: &str, scrypt_n: u32) -> Result<String> {
    // Generate 16-byte salt
    let salt = krusty_kms_crypto::random_bytes::<16>();

    // Derive encryption key
    let mut key = derive_scrypt_key(password.as_bytes(), &salt, scrypt_n)?;

    // Encrypt mnemonic bytes
    let payload = encrypt_with_key(mnemonic.as_bytes(), &key)?;

    // Zeroize derived key
    key.zeroize();

    // Build JSON
    let keystore = serde_json::json!({
        "version": 1,
        "crypto": {
            "cipher": "xchacha20-poly1305",
            "kdf": "scrypt",
            "kdfparams": {
                "n": scrypt_n,
                "r": 8,
                "p": 1,
                "dklen": 32,
                "salt": hex::encode(salt),
            },
            "nonce": hex::encode(&payload.nonce),
            "ciphertext": hex::encode(&payload.ciphertext),
        }
    });

    serde_json::to_string(&keystore)
        .map_err(|e| KmsError::SerializationError(format!("Failed to serialize keystore: {e}")))
}

/// Decrypt a native krusty-kms keystore (version 1) to recover the mnemonic.
///
/// # Arguments
/// * `keystore_json` - JSON keystore string produced by [`encrypt_keystore`]
/// * `password` - The password used during encryption
pub fn decrypt_keystore(keystore_json: &str, password: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(keystore_json)
        .map_err(|e| KmsError::DeserializationError(format!("Invalid keystore JSON: {e}")))?;

    let version = v["version"]
        .as_u64()
        .ok_or_else(|| KmsError::DeserializationError("Missing version field".to_string()))?;
    if version != 1 {
        return Err(KmsError::DeserializationError(format!(
            "Unsupported keystore version: {version}"
        )));
    }

    let crypto = &v["crypto"];

    let salt = hex::decode(
        crypto["kdfparams"]["salt"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing salt".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid salt hex: {e}")))?;

    let n = parse_u32_kdf_param(crypto["kdfparams"]["n"].as_u64(), "n")?;

    let nonce = hex::decode(
        crypto["nonce"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing nonce".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid nonce hex: {e}")))?;

    let ciphertext = hex::decode(
        crypto["ciphertext"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing ciphertext".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid ciphertext hex: {e}")))?;

    // Derive key
    let mut key = derive_scrypt_key(password.as_bytes(), &salt, n)?;

    let payload = crate::encryption::EncryptedPayload { nonce, ciphertext };
    let plaintext = decrypt_with_key(&payload, &key)?;

    // Zeroize derived key
    key.zeroize();

    String::from_utf8(plaintext)
        .map_err(|e| KmsError::CryptoError(format!("Decrypted keystore is not valid UTF-8: {e}")))
}

// ---------------------------------------------------------------------------
// ethers.js / Web3 Secret Storage (version 3) migration
// ---------------------------------------------------------------------------

/// Decrypt an ethers.js / Web3 Secret Storage keystore (version 3, scrypt KDF).
///
/// Supports the standard format:
/// ```json
/// {
///   "version": 3,
///   "crypto": {
///     "cipher": "aes-128-ctr",
///     "kdf": "scrypt",
///     "kdfparams": { "n": N, "r": 8, "p": 1, "dklen": 32, "salt": "hex" },
///     "cipherparams": { "iv": "hex" },
///     "ciphertext": "hex",
///     "mac": "hex"
///   }
/// }
/// ```
///
/// # Arguments
/// * `keystore_json` - JSON keystore string in ethers.js format
/// * `password` - The password used during encryption
///
/// # Returns
/// The decrypted content as a hex-encoded string (typically a private key).
pub fn decrypt_ethers_keystore(keystore_json: &str, password: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(keystore_json)
        .map_err(|e| KmsError::DeserializationError(format!("Invalid keystore JSON: {e}")))?;

    let version = v["version"]
        .as_u64()
        .ok_or_else(|| KmsError::DeserializationError("Missing version field".to_string()))?;
    if version != 3 {
        return Err(KmsError::DeserializationError(format!(
            "Expected ethers keystore version 3, got {version}"
        )));
    }

    let crypto = &v["crypto"];

    let kdf = crypto["kdf"]
        .as_str()
        .ok_or_else(|| KmsError::DeserializationError("Missing kdf field".to_string()))?;
    if kdf != "scrypt" {
        return Err(KmsError::DeserializationError(format!(
            "Unsupported KDF: {kdf} (only scrypt is supported)"
        )));
    }

    // Parse kdfparams
    let salt = hex::decode(
        crypto["kdfparams"]["salt"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing salt".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid salt hex: {e}")))?;

    let n = parse_u32_kdf_param(crypto["kdfparams"]["n"].as_u64(), "n")?;

    let r = parse_u32_kdf_param(crypto["kdfparams"]["r"].as_u64(), "r")?;

    let p = parse_u32_kdf_param(crypto["kdfparams"]["p"].as_u64(), "p")?;

    let dklen = crypto["kdfparams"]["dklen"]
        .as_u64()
        .ok_or_else(|| KmsError::DeserializationError("Missing kdfparams.dklen".to_string()))?
        as usize;

    // Parse cipher params
    let iv =
        hex::decode(crypto["cipherparams"]["iv"].as_str().ok_or_else(|| {
            KmsError::DeserializationError("Missing cipherparams.iv".to_string())
        })?)
        .map_err(|e| KmsError::DeserializationError(format!("Invalid IV hex: {e}")))?;

    let mut ciphertext = hex::decode(
        crypto["ciphertext"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing ciphertext".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid ciphertext hex: {e}")))?;

    let expected_mac = hex::decode(
        crypto["mac"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing mac".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid mac hex: {e}")))?;

    // Derive key via scrypt (validate N is a power of two in the allowed range)
    let log_n = scrypt_log_n(n)?;
    let params = ScryptParams::new(log_n, r, p, dklen)
        .map_err(|e| KmsError::CryptoError(format!("Invalid scrypt params: {e}")))?;
    let mut derived_key = vec![0u8; dklen];
    scrypt(password.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| KmsError::CryptoError(format!("Scrypt KDF failed: {e}")))?;

    // Verify MAC: Keccak256(derived_key[16..32] || ciphertext)
    let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
    mac_input.extend_from_slice(&derived_key[16..32]);
    mac_input.extend_from_slice(&ciphertext);
    let computed_mac = Keccak256::digest(&mac_input);

    // Constant-time MAC compare to avoid password-oracle timing leaks.
    if !bool::from(computed_mac.as_slice().ct_eq(expected_mac.as_slice())) {
        derived_key.zeroize();
        return Err(KmsError::CryptoError(
            "MAC verification failed: wrong password or corrupted keystore".to_string(),
        ));
    }

    // Decrypt with AES-128-CTR using derived_key[0..16] as key
    let aes_key = &derived_key[..16];
    let mut cipher = Aes128Ctr::new(aes_key.into(), iv.as_slice().into());
    cipher.apply_keystream(&mut ciphertext);
    // ciphertext is now plaintext

    // Zeroize derived key
    derived_key.zeroize();

    Ok(hex::encode(ciphertext))
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from a password and salt using scrypt (r=8, p=1).
fn derive_scrypt_key(password: &[u8], kdf_salt: &[u8], n: u32) -> Result<[u8; 32]> {
    let log_n = scrypt_log_n(n)?;
    let params = ScryptParams::new(log_n, 8, 1, 32)
        .map_err(|e| KmsError::CryptoError(format!("Invalid scrypt params: {e}")))?;
    let mut key = [u8::default(); 32];
    scrypt(password, kdf_salt, &params, &mut key)
        .map_err(|e| KmsError::CryptoError(format!("Scrypt KDF failed: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SCRYPT_N: u32 = 1024;

    fn test_password(offset: u8) -> String {
        (0..12)
            .map(|index| char::from(b'a' + index + offset))
            .collect()
    }

    #[test]
    fn encrypt_decrypt_keystore_roundtrip() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = test_password(0);

        let keystore_json = encrypt_keystore(mnemonic, &password, TEST_SCRYPT_N).unwrap();

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&keystore_json).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["crypto"]["cipher"], "xchacha20-poly1305");
        assert_eq!(parsed["crypto"]["kdf"], "scrypt");
        assert_eq!(parsed["crypto"]["kdfparams"]["n"], TEST_SCRYPT_N);

        let decrypted = decrypt_keystore(&keystore_json, &password).unwrap();
        assert_eq!(decrypted, mnemonic);
    }

    #[test]
    fn decrypt_keystore_wrong_password_fails() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = test_password(0);

        let keystore_json = encrypt_keystore(mnemonic, &password, TEST_SCRYPT_N).unwrap();

        let wrong_password = test_password(1);
        let result = decrypt_keystore(&keystore_json, &wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_ethers_keystore_known_vector() {
        // Build a test keystore by manually encrypting a known private key
        // using the ethers.js format (AES-128-CTR + scrypt).
        let private_key_bytes =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe512961708279f696ae35e0c2a1b5ce")
                .unwrap();
        let password = test_password(0);
        // Deterministic salt and IV for the test vector
        let salt = vec![0xab; 32];
        let iv = vec![0xcd; 16];

        // Derive key
        let log_n = scrypt_log_n(TEST_SCRYPT_N).unwrap();
        let params = ScryptParams::new(log_n, 8, 1, 32).unwrap();
        let mut derived_key = vec![0u8; 32];
        scrypt(password.as_bytes(), &salt, &params, &mut derived_key).unwrap();

        // Encrypt with AES-128-CTR
        let aes_key = &derived_key[..16];
        let mut ciphertext = private_key_bytes.clone();
        let mut cipher = Aes128Ctr::new(aes_key.into(), iv.as_slice().into());
        cipher.apply_keystream(&mut ciphertext);

        // Compute MAC
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&derived_key[16..32]);
        mac_input.extend_from_slice(&ciphertext);
        let mac = Keccak256::digest(&mac_input);

        // Build keystore JSON
        let keystore = serde_json::json!({
            "version": 3,
            "crypto": {
                "cipher": "aes-128-ctr",
                "kdf": "scrypt",
                "kdfparams": {
                    "n": TEST_SCRYPT_N,
                    "r": 8,
                    "p": 1,
                    "dklen": 32,
                    "salt": hex::encode(&salt),
                },
                "cipherparams": {
                    "iv": hex::encode(&iv),
                },
                "ciphertext": hex::encode(&ciphertext),
                "mac": hex::encode(mac.as_slice()),
            }
        });

        let keystore_json = serde_json::to_string(&keystore).unwrap();

        // Decrypt and verify
        let decrypted = decrypt_ethers_keystore(&keystore_json, &password).unwrap();
        assert_eq!(
            decrypted,
            "4c0883a69102937d6231471b5dbb6204fe512961708279f696ae35e0c2a1b5ce"
        );
    }

    #[test]
    fn decrypt_ethers_keystore_wrong_password_fails() {
        // Minimal valid keystore with wrong password
        let salt = vec![0xab; 32];
        let iv = vec![0xcd; 16];
        let password = test_password(0);

        let log_n = scrypt_log_n(TEST_SCRYPT_N).unwrap();
        let params = ScryptParams::new(log_n, 8, 1, 32).unwrap();
        let mut derived_key = vec![0u8; 32];
        scrypt(password.as_bytes(), &salt, &params, &mut derived_key).unwrap();

        let ciphertext = vec![0u8; 32];
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&derived_key[16..32]);
        mac_input.extend_from_slice(&ciphertext);
        let mac = Keccak256::digest(&mac_input);

        let keystore = serde_json::json!({
            "version": 3,
            "crypto": {
                "cipher": "aes-128-ctr",
                "kdf": "scrypt",
                "kdfparams": {
                    "n": TEST_SCRYPT_N,
                    "r": 8,
                    "p": 1,
                    "dklen": 32,
                    "salt": hex::encode(&salt),
                },
                "cipherparams": { "iv": hex::encode(&iv) },
                "ciphertext": hex::encode(&ciphertext),
                "mac": hex::encode(mac.as_slice()),
            }
        });

        let keystore_json = serde_json::to_string(&keystore).unwrap();

        let wrong_password = test_password(1);
        let result = decrypt_ethers_keystore(&keystore_json, &wrong_password);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("MAC verification failed"));
    }
}
