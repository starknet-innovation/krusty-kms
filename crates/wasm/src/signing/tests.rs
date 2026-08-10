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
fn test_stark_public_key_rejects_zero_key() {
    // Zero is a felt-parsable key; the public-key computation must error
    // instead of panicking on the identity point.
    assert!(stark_public_key("0x0").is_err());
    assert!(sign_stark_hash("0x0", TEST_STARK_HASH).is_err());
}

#[wasm_bindgen_test]
fn test_stark_public_key_rejects_curve_order_key() {
    // Felt-valid but >= curve order n: must not silently reduce mod n.
    let order = "0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";
    assert!(stark_public_key(order).is_err());
    assert!(sign_stark_hash(order, TEST_STARK_HASH).is_err());
}

#[wasm_bindgen_test]
fn test_sign_stark_hash_rejects_invalid_private_key() {
    let err = sign_stark_hash("not-hex", TEST_STARK_HASH).unwrap_err();
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
