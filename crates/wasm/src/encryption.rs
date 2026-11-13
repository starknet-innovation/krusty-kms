//! WASM bindings for private key and keystore encryption.
//!
//! Thin wrappers around `krusty_kms::encryption` and `krusty_kms::keystore`
//! that convert between hex strings and the internal byte representations.
//!
//! Passwords, private keys, mnemonics, symmetric keys, and plaintexts are
//! taken as owned strings and wiped when the call returns, and so is a decoded
//! symmetric key. Decrypted secrets are returned to the JS heap (see
//! [`crate`]).

use crate::secret_input::{decode_secret_hex, SecretHexError};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

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

/// Preserve the caller's exact JavaScript number before wasm-bindgen could
/// coerce it modulo 2^32 (for example, 2^32 + 1024 into 1024).
fn parse_scrypt_n(value: &JsValue) -> Result<u32, JsValue> {
    if value.as_f64().is_none() {
        return Err(crate::error::WasmError::SerializationError(
            "scryptN must be a number".to_string(),
        )
        .into());
    }
    crate::numeric_input::u32(value.clone(), "scryptN").map_err(|_| {
        crate::error::WasmError::SerializationError(
            "scryptN must be an exact u32 integer".to_string(),
        )
        .into()
    })
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
    private_key_hex: String,
    password: String,
    #[wasm_bindgen(unchecked_param_type = "number")] scrypt_n: JsValue,
) -> Result<WasmEncryptedKey, JsValue> {
    let (private_key_hex, password) = (Zeroizing::new(private_key_hex), Zeroizing::new(password));
    let scrypt_n = parse_scrypt_n(&scrypt_n)?;
    let result = encryption::encrypt_private_key(&private_key_hex, &password, scrypt_n)
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
/// Rejects KDF settings above the 256 MiB default memory budget. Use
/// `decryptPrivateKeyHighCost` deliberately for older high-cost ciphertexts.
#[wasm_bindgen(js_name = "decryptPrivateKey")]
pub fn decrypt_private_key(
    nonce: &str,
    salt: &str,
    encrypted_key: &str,
    password: String,
    #[wasm_bindgen(unchecked_param_type = "number")] scrypt_n: JsValue,
) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    let scrypt_n = parse_scrypt_n(&scrypt_n)?;
    decrypt_private_key_inner(nonce, salt, encrypted_key, password, scrypt_n, false)
}

/// Recover a legacy private key encrypted with an N that exceeds the default
/// memory budget. This may require up to about 1 GiB of scrypt scratch.
#[wasm_bindgen(js_name = "decryptPrivateKeyHighCost")]
pub fn decrypt_private_key_high_cost(
    nonce: &str,
    salt: &str,
    encrypted_key: &str,
    password: String,
    #[wasm_bindgen(unchecked_param_type = "number")] scrypt_n: JsValue,
) -> Result<String, JsValue> {
    let password = Zeroizing::new(password);
    let scrypt_n = parse_scrypt_n(&scrypt_n)?;
    decrypt_private_key_inner(nonce, salt, encrypted_key, password, scrypt_n, true)
}

fn decrypt_private_key_inner(
    nonce: &str,
    salt: &str,
    encrypted_key: &str,
    password: Zeroizing<String>,
    scrypt_n: u32,
    high_cost: bool,
) -> Result<String, JsValue> {
    if !high_cost && scrypt_n > encryption::DEFAULT_SCRYPT_N_MAX {
        return Err(JsValue::from(crate::error::WasmError::SerializationError(
            "scryptN exceeds the default memory ceiling; use decryptPrivateKeyHighCost for trusted legacy ciphertexts".to_string(),
        )));
    }
    if nonce.len() > 24 * 2 {
        return Err(crate::error::WasmError::SerializationError(
            "Invalid nonce: exceeds 24 bytes".to_string(),
        )
        .into());
    }
    if salt.len() > 128 * 2 {
        return Err(crate::error::WasmError::SerializationError(
            "Invalid salt: exceeds 128 bytes".to_string(),
        )
        .into());
    }
    if encrypted_key.len() > 1024 * 1024 * 2 {
        return Err(crate::error::WasmError::SerializationError(
            "Invalid encrypted key: exceeds 1 MiB".to_string(),
        )
        .into());
    }
    let encrypted = EncryptedKey {
        nonce: hex::decode(nonce)
            .map_err(|e| JsValue::from_str(&format!("Invalid nonce hex: {e}")))?,
        salt: hex::decode(salt)
            .map_err(|e| JsValue::from_str(&format!("Invalid salt hex: {e}")))?,
        encrypted_key: hex::decode(encrypted_key)
            .map_err(|e| JsValue::from_str(&format!("Invalid encrypted key hex: {e}")))?,
    };

    let result = if high_cost {
        encryption::decrypt_private_key(&encrypted, &password, scrypt_n)
    } else {
        encryption::decrypt_private_key_bounded(&encrypted, &password, scrypt_n)
    };
    result.map_err(|e| JsValue::from(crate::error::WasmError::from(e)))
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
pub fn encrypt_with_key(
    plaintext: String,
    key_hex: String,
) -> Result<WasmEncryptedPayload, JsValue> {
    let plaintext = Zeroizing::new(plaintext);
    let key = parse_symmetric_key(&Zeroizing::new(key_hex))?;

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
pub fn decrypt_with_key(nonce: &str, ciphertext: &str, key_hex: String) -> Result<String, JsValue> {
    let key = parse_symmetric_key(&Zeroizing::new(key_hex))?;

    let payload = EncryptedPayload {
        nonce: hex::decode(nonce)
            .map_err(|e| JsValue::from_str(&format!("Invalid nonce hex: {e}")))?,
        ciphertext: hex::decode(ciphertext)
            .map_err(|e| JsValue::from_str(&format!("Invalid ciphertext hex: {e}")))?,
    };

    let plaintext = encryption::decrypt_with_key(&payload, &key)
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))?;

    // A refused plaintext never reaches JS, so it is wiped here.
    String::from_utf8(plaintext).map_err(|e| {
        let error = format!("Decrypted data is not valid UTF-8: {}", e.utf8_error());
        drop(Zeroizing::new(e.into_bytes()));
        JsValue::from_str(&error)
    })
}

/// Decode a 64 hex-char symmetric key into a wiped buffer.
fn parse_symmetric_key(key_hex: &str) -> Result<Zeroizing<[u8; 32]>, JsValue> {
    decode_secret_hex(key_hex).map_err(|error| match error {
        SecretHexError::Hex(e) => JsValue::from_str(&format!("Invalid key hex: {e}")),
        SecretHexError::Length(_) => {
            JsValue::from_str("Key must be exactly 32 bytes (64 hex chars)")
        }
    })
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
pub fn encrypt_keystore(
    mnemonic: String,
    password: String,
    #[wasm_bindgen(unchecked_param_type = "number")] scrypt_n: JsValue,
) -> Result<String, JsValue> {
    let (mnemonic, password) = (Zeroizing::new(mnemonic), Zeroizing::new(password));
    let scrypt_n = parse_scrypt_n(&scrypt_n)?;
    keystore::encrypt_keystore(&mnemonic, &password, scrypt_n)
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))
}

/// Decrypt a krusty-kms keystore (version 1) to recover the mnemonic.
///
/// @param keystoreJson - JSON keystore string
/// @param password - The password used during encryption
/// @returns Decrypted mnemonic phrase
#[wasm_bindgen(js_name = "decryptKeystore")]
pub fn decrypt_keystore(keystore_json: &str, password: String) -> Result<String, JsValue> {
    keystore::decrypt_keystore(keystore_json, &Zeroizing::new(password))
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))
}

/// Decrypt an ethers.js / Web3 Secret Storage keystore (version 3, scrypt KDF).
///
/// @param keystoreJson - JSON keystore string in ethers.js format
/// @param password - The password used during encryption
/// @returns Decrypted content as hex string (typically a private key)
#[wasm_bindgen(js_name = "decryptEthersKeystore")]
pub fn decrypt_ethers_keystore(keystore_json: &str, password: String) -> Result<String, JsValue> {
    keystore::decrypt_ethers_keystore(keystore_json, &Zeroizing::new(password))
        .map_err(|e| JsValue::from(crate::error::WasmError::from(e)))
}

#[cfg(test)]
mod tests;
