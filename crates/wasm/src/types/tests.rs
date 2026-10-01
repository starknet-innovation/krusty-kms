use super::*;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn wasm_point_validation_rejects_invalid_hex() {
    assert!(WasmPoint {
        x: "not-hex".to_string(),
        y: "0x1".to_string(),
    }
    .validate()
    .is_err());
}

#[wasm_bindgen_test]
fn wasm_point_try_from_rejects_invalid_coordinates() {
    let error = krusty_kms_common::SerializablePoint::try_from(WasmPoint {
        x: "0x1".to_string(),
        y: "not-hex".to_string(),
    })
    .unwrap_err();
    assert!(matches!(error, WasmError::SerializationError(_)));
}

#[wasm_bindgen_test]
fn wasm_account_state_total_balance_rejects_overflow() {
    let state = WasmAccountState {
        balance: u128::MAX.to_string(),
        pending_balance: "1".to_string(),
        nonce: 0,
    };
    assert!(matches!(
        state.checked_total_balance(),
        Err(WasmError::InvalidAmount(_))
    ));
}

#[wasm_bindgen_test]
fn wasm_keypair_debug_redacts_private_key() {
    let g = krusty_kms_crypto::StarkCurve::generator();
    let affine = krusty_kms_crypto::StarkCurve::projective_to_affine(&g).unwrap();
    let kp = WasmKeypair::new(
        "0xdeadbeef".to_string(),
        format!("{:#x}", affine.x()),
        format!("{:#x}", affine.y()),
    )
    .expect("generator is a valid Stark curve point");
    let debug = format!("{kp:?}");
    assert!(debug.contains("***"));
    assert!(!debug.contains("deadbeef"));
}

#[wasm_bindgen_test]
fn wasm_keypair_rejects_off_curve_coordinates() {
    let err = validate_affine_public_key("0x1", "0x2").expect_err("off-curve");
    assert!(
        err.contains("not on the Stark curve"),
        "unexpected error: {err}"
    );
}

#[wasm_bindgen_test]
fn wasm_public_key_rejects_off_curve_coordinates() {
    let err = validate_affine_public_key("0x1", "0x2").expect_err("off-curve");
    assert!(
        err.contains("not on the Stark curve"),
        "unexpected error: {err}"
    );
}

#[wasm_bindgen_test]
fn wasm_nostr_keypair_debug_redacts_private_key() {
    let kp = WasmNostrKeypair::new("aabbccdd".to_string(), "11223344".to_string());
    let debug = format!("{kp:?}");
    assert!(debug.contains("***"));
    assert!(!debug.contains("aabbccdd"));
}

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[wasm_bindgen_test]
fn wasm_keypair_types_zeroize_on_drop() {
    // `free()` and the JS finalizer both drop the Rust value, so the marker is
    // what guarantees the owned private-key copy is wiped when JS lets go.
    assert_zeroize_on_drop::<WasmKeypair>();
    assert_zeroize_on_drop::<WasmStarkXOnlyKeypair>();
    assert_zeroize_on_drop::<WasmNostrKeypair>();
}

#[wasm_bindgen_test]
fn wasm_keypair_zeroize_wipes_only_the_private_key() {
    let mut kp = WasmKeypair {
        private_key: "0xdeadbeef".to_string(),
        public_key_x: "0x1".to_string(),
        public_key_y: "0x2".to_string(),
    };
    kp.zeroize();
    assert!(kp.private_key.is_empty());
    assert_eq!(
        (kp.public_key_x.as_str(), kp.public_key_y.as_str()),
        ("0x1", "0x2")
    );

    let mut x_only = WasmStarkXOnlyKeypair {
        private_key: "0xdeadbeef".to_string(),
        public_key_x: "0x1".to_string(),
    };
    x_only.zeroize();
    assert!(x_only.private_key.is_empty());
    assert_eq!(x_only.public_key_x, "0x1");

    let mut nostr = WasmNostrKeypair::new("aabbccdd".to_string(), "11223344".to_string());
    nostr.zeroize();
    assert!(nostr.private_key.is_empty());
    assert_eq!(nostr.public_key, "11223344");
}
