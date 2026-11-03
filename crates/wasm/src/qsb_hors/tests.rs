use super::*;
use wasm_bindgen_test::*;

// Public test fixtures from the draft BIP's reference.py. Never fund them.
const ALL_12: &str = "all all all all all all all all all all all all";
const VECTOR_TX: &str =
    "02000000011111111111111111111111111111111111111111111111111111111111111111\
                         0000000000ffffffff01e803000000000000015100000000";
const ROUND0: [u16; 8] = [7, 6, 5, 4, 3, 2, 1, 0];
const ROUND1: [u16; 7] = [149, 0, 75, 3, 140, 141, 8];

fn js_error_message(error: JsValue) -> String {
    js_sys::Reflect::get(&error, &JsValue::from_str("message"))
        .ok()
        .and_then(|value| value.as_string())
        .unwrap_or_default()
}

fn number(value: f64) -> JsValue {
    JsValue::from_f64(value)
}

fn numbers(values: &[f64]) -> JsValue {
    values
        .iter()
        .map(|&value| number(value))
        .collect::<js_sys::Array>()
        .into()
}

fn indices(values: &[u16]) -> JsValue {
    numbers(
        &values
            .iter()
            .map(|&value| f64::from(value))
            .collect::<Vec<_>>(),
    )
}

fn reveal(net: JsValue, vault_index: JsValue, round0: JsValue, round1: JsValue) -> String {
    js_error_message(
        reveal_qsb_preimages(ALL_12.into(), net, vault_index, round0, round1, None).unwrap_err(),
    )
}

fn digest_error(transaction_hex: &str) -> String {
    js_digest_error(transaction_hex.into())
}

fn js_digest_error(transaction_hex: JsString) -> String {
    js_error_message(
        qsb_reveal_digest(transaction_hex, indices(&ROUND0), indices(&ROUND1)).unwrap_err(),
    )
}

/// A valid one-input, one-output `T` of exactly `size` bytes, as hex built in
/// JS: only its short head ever exists in Rust.
fn transaction_hex_of_size(size: usize) -> JsString {
    // The script length in its canonical CompactSize: `fd` and a u16 when
    // that fits, otherwise `fe` and a u32 (59 fixed bytes plus the prefix).
    let (prefix, script_len) = match u16::try_from(size - 62) {
        Ok(len) if len >= 0xfd => (
            format!("fd{}", hex::encode(len.to_le_bytes())),
            usize::from(len),
        ),
        _ => {
            let len = size - 64;
            (
                format!(
                    "fe{}",
                    hex::encode(u32::try_from(len).unwrap().to_le_bytes())
                ),
                len,
            )
        }
    };
    let head = format!("{}01e803000000000000{prefix}", &VECTOR_TX[..92]);
    let script = JsString::from("51").repeat(i32::try_from(script_len).unwrap());
    let transaction = JsString::from(head)
        .concat(&script)
        .concat(&JsString::from("00000000"));
    assert_eq!(usize::try_from(transaction.length()).unwrap(), 2 * size);
    transaction
}

fn wasm_memory_bytes() -> usize {
    let memory: js_sys::WebAssembly::Memory = wasm_bindgen::memory().unchecked_into();
    let buffer: js_sys::ArrayBuffer = memory.buffer().unchecked_into();
    usize::try_from(buffer.byte_length()).unwrap()
}

#[wasm_bindgen_test]
fn commitments_match_the_reference() {
    let commitments =
        derive_qsb_commitments(ALL_12.into(), number(0.0), number(0.0), None).unwrap();
    assert_eq!(
        commitments.root,
        "11f1da69fa1ca2e5f9b23a4416c7c1be994933d2d8d06d5cf80dc4be02e0d3c1"
    );
    assert_eq!(commitments.round0.len(), 150);
    assert_eq!(commitments.round1.len(), 150);
    assert_eq!(
        commitments.round0[0],
        "296a1cf12ce73e492d0c7ff22b389d2b9ca3abaa"
    );
    assert_eq!(
        commitments.round1[149],
        "2d62908d953c4fa50a41d27627413be3b875b997"
    );
}

#[wasm_bindgen_test]
fn reveal_digest_matches_the_bip_vector() {
    let round0 = numbers(&[0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]);
    let round1 = indices(&[140, 141, 142, 143, 144, 145, 146]);
    let digest = qsb_reveal_digest(VECTOR_TX.into(), round0, round1).unwrap();
    assert_eq!(
        digest.binding,
        "d50c25f740af092cc115965a317beae0d72397eabd2b0495148de1c5e6bd2c4e"
    );
    assert_eq!(
        digest.digest,
        "eb9907c687e2a86336eb342d649b7c41e030f4eafe4129072377828e0eb57405"
    );
}

#[wasm_bindgen_test]
fn reveal_returns_fifteen_hex_strings_in_request_order() {
    let revealed = reveal_qsb_preimages(
        ALL_12.into(),
        number(0.0),
        number(0.0),
        indices(&ROUND0),
        indices(&ROUND1),
        None,
    )
    .unwrap();
    let revealed: Vec<String> = revealed
        .iter()
        .map(|value| value.as_string().unwrap())
        .collect();
    assert_eq!(revealed.len(), 15);
    assert_eq!(revealed[0], "0b6b0905f2690cfd7596ce9286b48e9267534453");
    assert_eq!(revealed[7], "830f76d7a7ad8db6374ff398c34781695bb71bdd");
    assert_eq!(revealed[8], "dd4f9caba9f69ddb708fe760dad229f38fdc9064");
    assert_eq!(revealed[14], "61330a1af9e6388986de70cf2b5f887623f10160");
    let with_passphrase = reveal_qsb_preimages(
        ALL_12.into(),
        number(0.0),
        number(0.0),
        indices(&ROUND0),
        indices(&ROUND1),
        Some("TREZOR".into()),
    )
    .unwrap();
    assert_ne!(with_passphrase.get(0).as_string().unwrap(), revealed[0]);
}

#[wasm_bindgen_test]
fn numbers_that_would_wrap_are_refused() {
    let ok = || (indices(&ROUND0), indices(&ROUND1));
    for net in [
        number(256.0),
        number(257.0),
        number(-1.0),
        number(0.5),
        JsValue::NULL,
        "0".into(),
    ] {
        let (round0, round1) = ok();
        let error = reveal(net, number(0.0), round0, round1);
        assert_eq!(error, "Invalid QSB namespace: expected an integer in range");
    }
    for vault_index in [
        number(4_294_967_303.0),
        number(-1.0),
        number(1.5),
        number(f64::NAN),
    ] {
        let (round0, round1) = ok();
        let error = reveal(number(0.0), vault_index, round0, round1);
        assert_eq!(
            error,
            "Invalid QSB vault index: expected an integer in range"
        );
    }
    for round0 in [
        numbers(&[65_536.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]),
        numbers(&[-1.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]),
        numbers(&[0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]),
        numbers(&[f64::NAN, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]),
    ] {
        let error = reveal(number(0.0), number(0.0), round0, indices(&ROUND1));
        assert_eq!(
            error,
            "Invalid QSB round 0 indices: expected an integer in range"
        );
    }
    // A typed array has already wrapped its values in JS (65536 is 0 here).
    for round0 in [
        js_sys::Uint16Array::from(&ROUND0[..]).into(),
        "0,1,2,3,4,5,6,7".into(),
        JsValue::NULL,
    ] {
        let error = reveal(number(0.0), number(0.0), round0, indices(&ROUND1));
        assert_eq!(error, "Invalid QSB round 0 indices: expected a plain array");
    }
}

#[wasm_bindgen_test]
fn index_array_lengths_are_checked_before_elements_are_read() {
    let nine = indices(&[0, 1, 2, 3, 4, 5, 6, 7, 8]);
    let error = reveal(number(0.0), number(0.0), nine, indices(&ROUND1));
    assert_eq!(
        error,
        "Invalid QSB round 0 indices: expected exactly 8, got 9"
    );
    let eight = indices(&[0, 1, 2, 3, 4, 5, 6, 7]);
    let error = reveal(number(0.0), number(0.0), indices(&ROUND0), eight);
    assert_eq!(
        error,
        "Invalid QSB round 1 indices: expected exactly 7, got 8"
    );
    // Unfilled arrays: reading any element would fail differently.
    for len in [1_000_000, 2_000_000_000] {
        let unfilled = js_sys::Array::new_with_length(len).into();
        let error = reveal(number(0.0), number(0.0), unfilled, indices(&ROUND1));
        assert_eq!(
            error,
            format!("Invalid QSB round 0 indices: expected exactly 8, got {len}")
        );
    }
}

#[wasm_bindgen_test]
fn profile_bounds_are_enforced_before_the_mnemonic_is_read() {
    let error = derive_qsb_commitments("not a mnemonic".into(), number(2.0), number(0.0), None)
        .unwrap_err();
    assert!(js_error_message(error).contains("QSB namespace 0x02"));
    let error = derive_qsb_commitments(
        "not a mnemonic".into(),
        number(1.0),
        number(2_147_483_648.0),
        None,
    )
    .unwrap_err();
    assert!(js_error_message(error).contains("must be below 2^31"));
    let error = reveal_qsb_preimages(
        "not a mnemonic".into(),
        number(0.0),
        number(0.0),
        indices(&[0, 1, 2, 3, 4, 5, 6, 0]),
        indices(&ROUND1),
        None,
    )
    .unwrap_err();
    assert!(js_error_message(error).contains("round 0 repeats index 0"));
    let error = reveal(
        number(0.0),
        number(0.0),
        indices(&ROUND0),
        indices(&ROUND1[..6]),
    );
    assert!(error.contains("round 1 indices: expected exactly 7, got 6"));
    let error = derive_qsb_commitments("not a mnemonic".into(), number(0.0), number(0.0), None)
        .unwrap_err();
    assert!(js_error_message(error).starts_with("Invalid mnemonic"));
}

#[wasm_bindgen_test]
fn transaction_hex_must_be_strict_and_the_transaction_exact() {
    let digest = digest_error;
    assert!(digest(&VECTOR_TX.to_uppercase()).contains("expected lowercase"));
    assert!(digest(&format!("0x{VECTOR_TX}")).starts_with("Invalid QSB transaction hex"));
    assert!(digest(&VECTOR_TX[1..]).starts_with("Invalid QSB transaction hex"));
    let with_script_sig = VECTOR_TX.replacen("0000000000ffffffff", "000000000151ffffffff", 1);
    assert!(digest(&with_script_sig).contains("non-empty scriptSig"));
    assert!(digest(&format!("{VECTOR_TX}00")).contains("trailing bytes"));
}

#[wasm_bindgen_test]
fn transaction_hex_is_bounded_in_js_before_it_is_copied() {
    let size = QSB_MAX_TRANSACTION_SIZE;
    let chars = 2 * size;
    let at_limit = transaction_hex_of_size(size);
    qsb_reveal_digest(at_limit, indices(&ROUND0), indices(&ROUND1)).unwrap();
    // At the limit but not a valid T: the parser refuses it, not the bound.
    let error = js_digest_error(JsString::from("00").repeat(i32::try_from(size).unwrap()));
    assert!(error.contains("QSB transaction: segwit marker"), "{error}");
    assert_eq!(
        js_digest_error(transaction_hex_of_size(size + 1)),
        format!(
            "Invalid QSB transaction hex: {} characters exceeds the {chars}-character limit",
            chars + 2
        )
    );
    // Tens of millions of characters, odd so that decoding would fail
    // differently: refused before WASM memory could hold a copy of it.
    let before = wasm_memory_bytes();
    let far_over = JsString::from("0").repeat(50_000_001);
    assert_eq!(
        js_digest_error(far_over),
        format!(
            "Invalid QSB transaction hex: 50000001 characters exceeds the {chars}-character limit"
        )
    );
    assert!(wasm_memory_bytes() - before < 50_000_001);
    // Untyped callers can pass anything; only a JS string is read.
    for value in [JsValue::from(42), js_sys::Array::new_with_length(8).into()] {
        assert_eq!(
            js_digest_error(value.unchecked_into()),
            "Invalid QSB transaction hex: expected a string"
        );
    }
}
