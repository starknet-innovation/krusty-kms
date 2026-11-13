//! Allocation limits for untrusted keystore text and encoded fields.

use krusty_kms_common::{KmsError, Result};

use super::{MAX_KEYSTORE_JSON_BYTES, MAX_KEYSTORE_SALT_BYTES};

/// A 24-word BIP-39 phrase is far below this; generated JSON stays importable.
pub(super) const MAX_NATIVE_MNEMONIC_BYTES: usize = 4096;

pub(super) fn validate_native_mnemonic_length(mnemonic: &str) -> Result<()> {
    if mnemonic.len() > MAX_NATIVE_MNEMONIC_BYTES {
        return Err(KmsError::SerializationError(format!(
            "mnemonic exceeds the {MAX_NATIVE_MNEMONIC_BYTES} byte limit"
        )));
    }
    Ok(())
}

/// Reject a too-large encoded salt before hex decoding allocates its bytes.
pub(super) fn decode_salt(value: &serde_json::Value) -> Result<Vec<u8>> {
    let encoded = value
        .as_str()
        .ok_or_else(|| KmsError::DeserializationError("Missing salt".to_string()))?;
    if encoded.len() > MAX_KEYSTORE_SALT_BYTES * 2 {
        return Err(KmsError::DeserializationError(format!(
            "kdfparams.salt exceeds the {MAX_KEYSTORE_SALT_BYTES} byte limit"
        )));
    }
    let salt = hex::decode(encoded)
        .map_err(|e| KmsError::DeserializationError(format!("Invalid salt hex: {e}")))?;
    if salt.len() > MAX_KEYSTORE_SALT_BYTES {
        return Err(KmsError::DeserializationError(format!(
            "kdfparams.salt is {} bytes (limit {MAX_KEYSTORE_SALT_BYTES})",
            salt.len()
        )));
    }
    Ok(salt)
}

/// Bound the whole serialized keystore before `serde_json` allocates a tree.
pub(super) fn parse_keystore_json(keystore_json: &str) -> Result<serde_json::Value> {
    if keystore_json.len() > MAX_KEYSTORE_JSON_BYTES {
        return Err(KmsError::DeserializationError(format!(
            "keystore JSON exceeds the {MAX_KEYSTORE_JSON_BYTES} byte limit"
        )));
    }
    serde_json::from_str(keystore_json)
        .map_err(|e| KmsError::DeserializationError(format!("Invalid keystore JSON: {e}")))
}
