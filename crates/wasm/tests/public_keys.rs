//! Public-key strings arrive from untrusted counterparties (a Tongo recipient
//! key shared out of band, an auditor key from remote config). They must be
//! refused with an error: a panic on wasm32 traps the whole module.
use krusty_kms_wasm::{
    deserialize_public_key, generate_transfer_proof, get_generator, WasmAccount, WasmTransferParams,
};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

fn message(error: JsValue) -> String {
    error
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(&error, &JsValue::from_str("message"))
                .ok()
                .and_then(|value| value.as_string())
        })
        .unwrap_or_default()
}

/// 63 ASCII hex digits, U+00E9 (two bytes, straddling byte offset 64), 63
/// more: 128 bytes after the prefix but 127 characters, so a byte-length
/// check passes and a byte-offset split at 64 lands inside the character.
fn straddling_public_key() -> String {
    format!("0x{}\u{e9}{}", "a".repeat(63), "a".repeat(63))
}

#[wasm_bindgen_test]
fn deserialize_public_key_refuses_a_char_boundary_straddling_key() {
    let key = straddling_public_key();
    assert_eq!(key.len(), 130);
    let error = message(deserialize_public_key(&key).unwrap_err());
    assert!(error.contains("hex digits"), "{error}");

    let error = message(deserialize_public_key(&format!("0x{}", "g".repeat(128))).unwrap_err());
    assert!(error.contains("hex digits"), "{error}");
}

#[wasm_bindgen_test]
fn transfer_proof_refuses_a_char_boundary_straddling_recipient_key() {
    let account = WasmAccount::from_private_key("0x1".into(), "0x2").expect("account");
    let g = get_generator();
    let params = WasmTransferParams::new(
        straddling_public_key(),
        "1".into(),
        "0x1".into(),
        "0x1".into(),
        "0x1".into(),
        "0x1".into(),
        g.x.clone(),
        g.y.clone(),
        g.x.clone(),
        g.y.clone(),
    );
    let error = message(generate_transfer_proof(&account, &params).unwrap_err());
    assert!(error.starts_with("Invalid public key:"), "{error}");
    assert!(error.contains("hex digits"), "{error}");
}
