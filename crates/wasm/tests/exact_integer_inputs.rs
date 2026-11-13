#![cfg(target_arch = "wasm32")]

use krusty_kms_wasm::{account, discovery, proof, tx_hash, types, utils};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

fn error_contains<T>(result: Result<T, JsValue>, expected: &str) {
    let error = result.err().expect("invalid integer must fail");
    assert!(
        error.as_string().unwrap_or_default().contains(expected),
        "expected error containing {expected:?}, got {error:?}"
    );
}

#[wasm_bindgen_test]
fn rejects_wrapped_derivation_and_discovery_indices() {
    let wrapped = JsValue::from_f64(4_294_967_296.0);
    error_contains(
        account::derive_keypair(
            "synthetic mnemonic".into(),
            wrapped.clone(),
            JsValue::from_f64(0.0),
            None,
        ),
        "address index",
    );
    error_contains(
        discovery::generate_account_candidates("synthetic mnemonic".into(), wrapped),
        "max index",
    );
    error_contains(
        account::generate_mnemonic(JsValue::from_f64(256.0)),
        "word count",
    );
}

#[wasm_bindgen_test]
fn rejects_wrapped_random_length() {
    let wrapped = JsValue::from_f64(4_294_967_296.0);
    error_contains(utils::random_bytes_hex(wrapped), "random byte length");
}

#[wasm_bindgen_test]
fn rejects_wrapped_proof_width_and_da_mode() {
    let params = proof::WasmTransferParams::new(
        "0x1".into(),
        "1".into(),
        "0x1".into(),
        "0x1".into(),
        "0x1".into(),
        "0x1".into(),
        "0x1".into(),
        "0x1".into(),
        "0x1".into(),
        "0x1".into(),
    );
    error_contains(params.with_bit_size(JsValue::from_f64(256.0)), "bit size");

    error_contains(
        tx_hash::compute_invoke_transaction_hash_v3(
            "0x1",
            vec![],
            "0x1",
            "0x1",
            "0",
            JsValue::NULL,
            vec![],
            JsValue::from_f64(256.0),
            JsValue::from_f64(0.0),
            vec![],
            None,
        ),
        "nonce DA mode",
    );
}

#[wasm_bindgen_test]
fn rejects_nonce_above_u64() {
    let overflow = js_sys::BigInt::new(&JsValue::from_str("18446744073709551616")).unwrap();
    error_contains(
        types::WasmAccountState::new("0".into(), "0".into(), overflow.into()),
        "transaction nonce",
    );

    let account = account::WasmAccount::from_private_key("0x1".into(), "0x1").unwrap();
    let cipher = types::WasmCiphertext::new("0".into(), "0".into(), "0".into(), "0".into());
    let overflow = js_sys::BigInt::new(&JsValue::from_str("18446744073709551616")).unwrap();
    error_contains(
        account.decrypt_balance(&cipher, overflow.into()),
        "max search",
    );
}
