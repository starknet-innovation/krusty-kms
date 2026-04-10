//! WASM bindings for private key and keystore encryption.
//!
//! Thin wrappers around `krusty_kms::encryption` and `krusty_kms::keystore`
//! that convert between hex strings and the internal byte representations.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use krusty_kms::encryption::{self, EncryptedKey, EncryptedPayload};
use krusty_kms::keystore;

/// Encrypted private key returned to JavaScript (all fields hex-encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmEncryptedKey {
    /// Hex-encoded 24-byte nonce.
    pub nonce: String,
    /// Hex-encoded 16-byte salt.
    pub salt: String,
    /// Hex-encoded ciphertext (includes Poly1305 tag).
    #[wasm_bindgen(js_name = "encryptedKey")]
    pub encrypted_key: String,
}

/// Encrypted payload returned to JavaScript (all fields hex-encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmEncryptedPayload {
    /// Hex-encoded 24-byte nonce.
    pub nonce: String,
    /// Hex-encoded ciphertext (includes Poly1305 tag).
    pub ciphertext: String,
}

// ---------------------------------------------------------------------------
// Private key encryption
// ---------------------------------------------------------------------------

/// Encrypt a hex-encoded private key with a password (scrypt + XChaCha20-Poly1305).
///
/// @param privateKeyHex - Private key in hex (with or without 0x prefix)
/// @param password - Encryption password
/// @param scryptN - Scrypt cost parameter N (power of 2, e.g. 32768)
/// @returns Encrypted key with hex-encoded nonce, salt, and ciphertext
#[wasm_bindgen(js_name = "encryptPrivateKey")]
pub fn encrypt_private_key(
    private_key_hex: &str,
    password: &str,
    scrypt_n: u32,
) -> Result<WasmEncryptedKey, JsValue> {
    let result = encryption::encrypt_private_key(private_key_hex, password, scrypt_n)
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))?;

    Ok(WasmEncryptedKey {
        nonce: hex::encode(&result.nonce),
        salt: hex::encode(&result.salt),
        encrypted_key: hex::encode(&result.encrypted_key),
    })
}

/// Decrypt a private key that was encrypted with `encryptPrivateKey`.
///
/// @param nonce - Hex-encoded 24-byte nonce
/// @param salt - Hex-encoded 16-byte salt
/// @param encryptedKey - Hex-encoded ciphertext
/// @param password - The password used during encryption
/// @param scryptN - The same scrypt cost parameter used during encryption
/// @returns Hex-encoded private key (no 0x prefix)
#[wasm_bindgen(js_name = "decryptPrivateKey")]
pub fn decrypt_private_key(
    nonce: &str,
    salt: &str,
    encrypted_key: &str,
    password: &str,
    scrypt_n: u32,
) -> Result<String, JsValue> {
    let encrypted = EncryptedKey {
        nonce: hex::decode(nonce)
            .map_err(|e| JsValue::from_str(&format!("Invalid nonce hex: {e}")))?,
        salt: hex::decode(salt)
            .map_err(|e| JsValue::from_str(&format!("Invalid salt hex: {e}")))?,
        encrypted_key: hex::decode(encrypted_key)
            .map_err(|e| JsValue::from_str(&format!("Invalid encrypted key hex: {e}")))?,
    };

    encryption::decrypt_private_key(&encrypted, password, scrypt_n)
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))
}

// ---------------------------------------------------------------------------
// Direct key-based encryption
// ---------------------------------------------------------------------------

/// Encrypt a plaintext string with a pre-derived 32-byte key.
///
/// @param plaintext - UTF-8 string to encrypt
/// @param keyHex - Hex-encoded 32-byte key (64 hex chars)
/// @returns Encrypted payload with hex-encoded nonce and ciphertext
#[wasm_bindgen(js_name = "encryptWithKey")]
pub fn encrypt_with_key(plaintext: &str, key_hex: &str) -> Result<WasmEncryptedPayload, JsValue> {
    let key_bytes =
        hex::decode(key_hex).map_err(|e| JsValue::from_str(&format!("Invalid key hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str(
            "Key must be exactly 32 bytes (64 hex chars)",
        ));
    }
    let key: [u8; 32] = key_bytes.try_into().unwrap();

    let result = encryption::encrypt_with_key(plaintext.as_bytes(), &key)
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))?;

    Ok(WasmEncryptedPayload {
        nonce: hex::encode(&result.nonce),
        ciphertext: hex::encode(&result.ciphertext),
    })
}

/// Decrypt data that was encrypted with `encryptWithKey`.
///
/// @param nonce - Hex-encoded 24-byte nonce
/// @param ciphertext - Hex-encoded ciphertext
/// @param keyHex - Hex-encoded 32-byte key (64 hex chars)
/// @returns Decrypted plaintext as a UTF-8 string
#[wasm_bindgen(js_name = "decryptWithKey")]
pub fn decrypt_with_key(nonce: &str, ciphertext: &str, key_hex: &str) -> Result<String, JsValue> {
    let key_bytes =
        hex::decode(key_hex).map_err(|e| JsValue::from_str(&format!("Invalid key hex: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str(
            "Key must be exactly 32 bytes (64 hex chars)",
        ));
    }
    let key: [u8; 32] = key_bytes.try_into().unwrap();

    let payload = EncryptedPayload {
        nonce: hex::decode(nonce)
            .map_err(|e| JsValue::from_str(&format!("Invalid nonce hex: {e}")))?,
        ciphertext: hex::decode(ciphertext)
            .map_err(|e| JsValue::from_str(&format!("Invalid ciphertext hex: {e}")))?,
    };

    let plaintext = encryption::decrypt_with_key(&payload, &key)
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| JsValue::from_str(&format!("Decrypted data is not valid UTF-8: {e}")))
}

// ---------------------------------------------------------------------------
// Keystore operations
// ---------------------------------------------------------------------------

/// Encrypt a mnemonic into a JSON keystore string (krusty-kms format, version 1).
///
/// @param mnemonic - Mnemonic phrase to encrypt
/// @param password - Encryption password
/// @param scryptN - Scrypt cost parameter N (power of 2, e.g. 32768)
/// @returns JSON keystore string
#[wasm_bindgen(js_name = "encryptKeystore")]
pub fn encrypt_keystore(mnemonic: &str, password: &str, scrypt_n: u32) -> Result<String, JsValue> {
    keystore::encrypt_keystore(mnemonic, password, scrypt_n)
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))
}

/// Decrypt a krusty-kms keystore (version 1) to recover the mnemonic.
///
/// @param keystoreJson - JSON keystore string
/// @param password - The password used during encryption
/// @returns Decrypted mnemonic phrase
#[wasm_bindgen(js_name = "decryptKeystore")]
pub fn decrypt_keystore(keystore_json: &str, password: &str) -> Result<String, JsValue> {
    keystore::decrypt_keystore(keystore_json, password)
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))
}

/// Decrypt an ethers.js / Web3 Secret Storage keystore (version 3, scrypt KDF).
///
/// @param keystoreJson - JSON keystore string in ethers.js format
/// @param password - The password used during encryption
/// @returns Decrypted content as hex string (typically a private key)
#[wasm_bindgen(js_name = "decryptEthersKeystore")]
pub fn decrypt_ethers_keystore(keystore_json: &str, password: &str) -> Result<String, JsValue> {
    keystore::decrypt_ethers_keystore(keystore_json, password)
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    const TEST_SCRYPT_N: u32 = 1024;

    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_private_key_roundtrip() {
        let private_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let password = "hunter2";

        let encrypted = encrypt_private_key(private_key, password, TEST_SCRYPT_N).unwrap();

        let decrypted = decrypt_private_key(
            &encrypted.nonce,
            &encrypted.salt,
            &encrypted.encrypted_key,
            password,
            TEST_SCRYPT_N,
        )
        .unwrap();

        assert_eq!(decrypted, private_key);
    }

    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_with_key_roundtrip() {
        let plaintext = "some secret data";
        let key_hex = "0101010101010101010101010101010101010101010101010101010101010101";

        let encrypted = encrypt_with_key(plaintext, key_hex).unwrap();

        let decrypted = decrypt_with_key(&encrypted.nonce, &encrypted.ciphertext, key_hex).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_keystore_roundtrip() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "test-password";

        let keystore_json = encrypt_keystore(mnemonic, password, TEST_SCRYPT_N).unwrap();
        let decrypted = decrypt_keystore(&keystore_json, password).unwrap();

        assert_eq!(decrypted, mnemonic);
    }
}
