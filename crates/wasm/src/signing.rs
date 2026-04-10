//! WASM bindings for Stark and Nostr signing operations.
//!
//! Provides JavaScript-accessible APIs for:
//! - Stark ECDSA signing (Category A)
//! - Nostr BIP-340 Schnorr signing (Category F)

use crate::types::{WasmNostrSignature, WasmStarkSignature};
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

// ============================================================================
// Stark Signing (Category A)
// ============================================================================

/// Derive the Stark public key corresponding to a private key.
///
/// # Arguments
/// * `private_key` - Stark private key as hex string (0x-prefixed)
///
/// # Returns
/// The public key as a hex string (0x-prefixed)
#[wasm_bindgen(js_name = "starkPublicKey")]
pub fn stark_public_key(private_key: &str) -> Result<String, JsValue> {
    let sk = Felt::from_hex(private_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid private key hex: {e}")))?;

    let pk = krusty_kms::stark_public_key(&sk);
    Ok(format!("{:#x}", pk))
}

/// Sign a message hash using Stark ECDSA.
///
/// Uses deterministic RFC-6979 nonce generation.
///
/// # Arguments
/// * `private_key` - Stark private key as hex string (0x-prefixed)
/// * `msg_hash` - Message hash as hex string (0x-prefixed)
///
/// # Returns
/// Signature with r, s components and public key (all 0x-prefixed hex)
#[wasm_bindgen(js_name = "signStarkHash")]
pub fn sign_stark_hash(private_key: &str, msg_hash: &str) -> Result<WasmStarkSignature, JsValue> {
    let sk = Felt::from_hex(private_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid private key hex: {e}")))?;
    let hash = Felt::from_hex(msg_hash)
        .map_err(|e| JsValue::from_str(&format!("Invalid message hash hex: {e}")))?;

    let sig = krusty_kms::sign_stark_hash(&sk, &hash)
        .map_err(|e| JsValue::from_str(&format!("Stark signing failed: {e}")))?;

    Ok(WasmStarkSignature {
        r: format!("{:#x}", sig.r),
        s: format!("{:#x}", sig.s),
        public_key: format!("{:#x}", sig.public_key),
    })
}

// ============================================================================
// Nostr Signing (Category F)
// ============================================================================

/// Parse a 64 hex-char Nostr private key (no 0x prefix) into [u8; 32].
fn parse_nostr_private_key(hex_str: &str) -> Result<[u8; 32], JsValue> {
    let hex_str = hex_str.trim();
    if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        return Err(JsValue::from_str(
            "Nostr private key must not have 0x prefix",
        ));
    }
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsValue::from_str(&format!("Invalid Nostr private key hex: {e}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        JsValue::from_str("Nostr private key must be exactly 32 bytes (64 hex chars)")
    })?;
    Ok(arr)
}

/// Parse a 64 hex-char Nostr event id (no 0x prefix) into [u8; 32].
fn parse_nostr_event_id(hex_str: &str) -> Result<[u8; 32], JsValue> {
    let hex_str = hex_str.trim();
    if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        return Err(JsValue::from_str("Nostr event id must not have 0x prefix"));
    }
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsValue::from_str(&format!("Invalid Nostr event id hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Nostr event id must be exactly 32 bytes (64 hex chars)"))?;
    Ok(arr)
}

/// Parse hex-encoded message bytes (may have optional 0x prefix).
fn parse_hex_message(hex_str: &str) -> Result<Vec<u8>, JsValue> {
    let hex_str = hex_str
        .trim()
        .strip_prefix("0x")
        .or_else(|| hex_str.trim().strip_prefix("0X"))
        .unwrap_or(hex_str.trim());
    hex::decode(hex_str).map_err(|e| JsValue::from_str(&format!("Invalid message hex: {e}")))
}

/// Convert a `NostrSignature` to the WASM-friendly type.
fn nostr_sig_to_wasm(sig: krusty_kms::NostrSignature) -> WasmNostrSignature {
    WasmNostrSignature {
        public_key: hex::encode(sig.public_key),
        signature: hex::encode(sig.signature),
    }
}

/// Derive the x-only Nostr public key for a secp256k1 private key.
///
/// # Arguments
/// * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
///
/// # Returns
/// x-only public key as 64 hex chars (no 0x prefix)
#[wasm_bindgen(js_name = "nostrPublicKey")]
pub fn nostr_public_key(private_key: &str) -> Result<String, JsValue> {
    let sk = parse_nostr_private_key(private_key)?;
    let pk = krusty_kms::nostr_public_key(&sk)
        .map_err(|e| JsValue::from_str(&format!("Nostr public key derivation failed: {e}")))?;
    Ok(hex::encode(pk))
}

/// Sign a 32-byte Nostr event id using BIP-340 Schnorr.
///
/// # Arguments
/// * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
/// * `event_id` - 64 hex chars (no 0x prefix), the event id to sign
///
/// # Returns
/// Signature result with public key and signature (both hex, no 0x prefix)
#[wasm_bindgen(js_name = "signNostrEventId")]
pub fn sign_nostr_event_id(
    private_key: &str,
    event_id: &str,
) -> Result<WasmNostrSignature, JsValue> {
    let sk = parse_nostr_private_key(private_key)?;
    let eid = parse_nostr_event_id(event_id)?;

    let sig = krusty_kms::sign_nostr_event_id(&sk, &eid)
        .map_err(|e| JsValue::from_str(&format!("Nostr event signing failed: {e}")))?;

    Ok(nostr_sig_to_wasm(sig))
}

/// Sign an arbitrary message using BIP-340 Schnorr.
///
/// # Arguments
/// * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
/// * `message` - hex-encoded bytes (may have optional 0x prefix)
///
/// # Returns
/// Signature result with public key and signature (both hex, no 0x prefix)
#[wasm_bindgen(js_name = "signNostrMessage")]
pub fn sign_nostr_message(private_key: &str, message: &str) -> Result<WasmNostrSignature, JsValue> {
    let sk = parse_nostr_private_key(private_key)?;
    let msg = parse_hex_message(message)?;

    let sig = krusty_kms::sign_nostr_message(&sk, &msg)
        .map_err(|e| JsValue::from_str(&format!("Nostr message signing failed: {e}")))?;

    Ok(nostr_sig_to_wasm(sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    // A well-known test private key (not used for anything real).
    const TEST_STARK_SK: &str = "0x1";
    const TEST_STARK_HASH: &str = "0x2";

    fn js_error_message(error: JsValue) -> String {
        error
            .as_string()
            .or_else(|| {
                js_sys::Reflect::get(&error, &JsValue::from_str("message"))
                    .ok()
                    .and_then(|value| value.as_string())
            })
            .unwrap_or_default()
    }

    // ========================================================================
    // Stark signing tests
    // ========================================================================

    #[wasm_bindgen_test]
    fn test_stark_public_key_deterministic() {
        let pk1 = stark_public_key(TEST_STARK_SK).unwrap();
        let pk2 = stark_public_key(TEST_STARK_SK).unwrap();
        assert_eq!(pk1, pk2);
        assert!(pk1.starts_with("0x"));
    }

    #[wasm_bindgen_test]
    fn test_sign_stark_hash_deterministic() {
        let sig1 = sign_stark_hash(TEST_STARK_SK, TEST_STARK_HASH).unwrap();
        let sig2 = sign_stark_hash(TEST_STARK_SK, TEST_STARK_HASH).unwrap();
        assert_eq!(sig1.r, sig2.r);
        assert_eq!(sig1.s, sig2.s);
        assert_eq!(sig1.public_key, sig2.public_key);
    }

    #[wasm_bindgen_test]
    fn test_sign_stark_hash_public_key_matches() {
        let pk = stark_public_key(TEST_STARK_SK).unwrap();
        let sig = sign_stark_hash(TEST_STARK_SK, TEST_STARK_HASH).unwrap();
        assert_eq!(sig.public_key, pk);
    }

    #[wasm_bindgen_test]
    fn test_stark_public_key_rejects_invalid_hex() {
        let err = stark_public_key("not-hex").unwrap_err();
        let msg = js_error_message(err);
        assert!(msg.contains("Invalid private key hex"));
    }

    #[wasm_bindgen_test]
    fn test_sign_stark_hash_rejects_invalid_private_key() {
        let err = sign_stark_hash("bad", TEST_STARK_HASH).unwrap_err();
        let msg = js_error_message(err);
        assert!(msg.contains("Invalid private key hex"));
    }

    #[wasm_bindgen_test]
    fn test_sign_stark_hash_rejects_invalid_hash() {
        let err = sign_stark_hash(TEST_STARK_SK, "zzz").unwrap_err();
        let msg = js_error_message(err);
        assert!(msg.contains("Invalid message hash hex"));
    }

    // ========================================================================
    // Nostr signing tests
    // ========================================================================

    /// Derive a deterministic Nostr test key from the test mnemonic.
    fn test_nostr_private_key() -> String {
        let mnemonic =
            "habit hope tip crystal because grunt nation idea electric witness alert like";
        let kp = crate::account::derive_nostr_keypair(mnemonic, 0, 0, None).unwrap();
        kp.private_key
    }

    #[wasm_bindgen_test]
    fn test_nostr_public_key_deterministic() {
        let sk = test_nostr_private_key();
        let pk1 = nostr_public_key(&sk).unwrap();
        let pk2 = nostr_public_key(&sk).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(pk1.len(), 64);
        assert!(!pk1.starts_with("0x"));
    }

    #[wasm_bindgen_test]
    fn test_sign_nostr_event_id_deterministic() {
        let sk = test_nostr_private_key();
        // Fake 32-byte event id
        let event_id = "a".repeat(64);
        let sig1 = sign_nostr_event_id(&sk, &event_id).unwrap();
        let sig2 = sign_nostr_event_id(&sk, &event_id).unwrap();
        assert_eq!(sig1.public_key, sig2.public_key);
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[wasm_bindgen_test]
    fn test_sign_nostr_event_id_public_key_matches() {
        let sk = test_nostr_private_key();
        let pk = nostr_public_key(&sk).unwrap();
        let event_id = "b".repeat(64);
        let sig = sign_nostr_event_id(&sk, &event_id).unwrap();
        assert_eq!(sig.public_key, pk);
    }

    #[wasm_bindgen_test]
    fn test_sign_nostr_message_deterministic() {
        let sk = test_nostr_private_key();
        let message = "deadbeef";
        let sig1 = sign_nostr_message(&sk, message).unwrap();
        let sig2 = sign_nostr_message(&sk, message).unwrap();
        assert_eq!(sig1.public_key, sig2.public_key);
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[wasm_bindgen_test]
    fn test_sign_nostr_message_with_0x_prefix() {
        let sk = test_nostr_private_key();
        let sig1 = sign_nostr_message(&sk, "deadbeef").unwrap();
        let sig2 = sign_nostr_message(&sk, "0xdeadbeef").unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[wasm_bindgen_test]
    fn test_nostr_public_key_rejects_invalid_hex() {
        let err = nostr_public_key("not-valid-hex").unwrap_err();
        let msg = js_error_message(err);
        assert!(msg.contains("Invalid Nostr private key hex"));
    }

    #[wasm_bindgen_test]
    fn test_nostr_public_key_rejects_0x_prefix() {
        // Valid 32 bytes but with 0x prefix
        let err = nostr_public_key(&format!("0x{}", "aa".repeat(32))).unwrap_err();
        let msg = js_error_message(err);
        assert!(msg.contains("must not have 0x prefix"));
    }

    #[wasm_bindgen_test]
    fn test_nostr_public_key_rejects_wrong_length() {
        let err = nostr_public_key("aabb").unwrap_err();
        let msg = js_error_message(err);
        assert!(msg.contains("exactly 32 bytes"));
    }

    #[wasm_bindgen_test]
    fn test_sign_nostr_event_id_rejects_wrong_length() {
        let sk = test_nostr_private_key();
        let err = sign_nostr_event_id(&sk, "aabb").unwrap_err();
        let msg = js_error_message(err);
        assert!(msg.contains("exactly 32 bytes"));
    }

    #[wasm_bindgen_test]
    fn test_nostr_signature_format() {
        let sk = test_nostr_private_key();
        let event_id = "c".repeat(64);
        let sig = sign_nostr_event_id(&sk, &event_id).unwrap();
        // Public key: 64 hex chars, no 0x prefix
        assert_eq!(sig.public_key.len(), 64);
        assert!(!sig.public_key.starts_with("0x"));
        // Signature: 128 hex chars, no 0x prefix
        assert_eq!(sig.signature.len(), 128);
        assert!(!sig.signature.starts_with("0x"));
        // Both should be valid hex
        assert!(hex::decode(&sig.public_key).is_ok());
        assert!(hex::decode(&sig.signature).is_ok());
    }
}
