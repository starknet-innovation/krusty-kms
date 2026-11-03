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
        reveal_qsb_preimages(ALL_12, net, vault_index, round0, round1, None).unwrap_err(),
    )
}

#[wasm_bindgen_test]
fn commitments_match_the_reference() {
    let commitments = derive_qsb_commitments(ALL_12, number(0.0), number(0.0), None).unwrap();
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
    let digest = qsb_reveal_digest(VECTOR_TX, round0, round1).unwrap();
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
        ALL_12,
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

    // Typed arrays carry the same indices.
    let typed = reveal_qsb_preimages(
        ALL_12,
        number(0.0),
        number(0.0),
        js_sys::Uint16Array::from(&ROUND0[..]).into(),
        js_sys::Uint16Array::from(&ROUND1[..]).into(),
        None,
    )
    .unwrap();
    assert_eq!(typed.get(14).as_string().unwrap(), revealed[14]);
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
        assert_eq!(error, "Invalid QSB namespace: expected integers in range");
    }
    for vault_index in [
        number(4_294_967_303.0),
        number(-1.0),
        number(1.5),
        number(f64::NAN),
    ] {
        let (round0, round1) = ok();
        let error = reveal(number(0.0), vault_index, round0, round1);
        assert_eq!(error, "Invalid QSB vault index: expected integers in range");
    }
    for round0 in [
        numbers(&[65_536.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]),
        numbers(&[-1.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]),
        numbers(&[0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]),
        "0,1,2,3,4,5,6,7".into(),
    ] {
        let error = reveal(number(0.0), number(0.0), round0, indices(&ROUND1));
        assert_eq!(
            error,
            "Invalid QSB round 0 indices: expected integers in range"
        );
    }
}

#[wasm_bindgen_test]
fn profile_bounds_are_enforced_before_the_mnemonic_is_read() {
    let error =
        derive_qsb_commitments("not a mnemonic", number(2.0), number(0.0), None).unwrap_err();
    assert!(js_error_message(error).contains("QSB namespace 0x02"));
    let error =
        derive_qsb_commitments("not a mnemonic", number(1.0), number(2_147_483_648.0), None)
            .unwrap_err();
    assert!(js_error_message(error).contains("must be below 2^31"));
    let error = reveal_qsb_preimages(
        "not a mnemonic",
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
    assert!(error.contains("round 1 needs exactly 7 indices"));
    let error =
        derive_qsb_commitments("not a mnemonic", number(0.0), number(0.0), None).unwrap_err();
    assert!(js_error_message(error).starts_with("Invalid mnemonic"));
}

#[wasm_bindgen_test]
fn transaction_hex_must_be_strict_and_the_transaction_exact() {
    let digest = |hex: &str| {
        js_error_message(qsb_reveal_digest(hex, indices(&ROUND0), indices(&ROUND1)).unwrap_err())
    };
    assert!(digest(&VECTOR_TX.to_uppercase()).contains("expected lowercase"));
    assert!(digest(&format!("0x{VECTOR_TX}")).starts_with("Invalid QSB transaction hex"));
    assert!(digest(&VECTOR_TX[1..]).starts_with("Invalid QSB transaction hex"));
    let with_script_sig = VECTOR_TX.replacen("0000000000ffffffff", "000000000151ffffffff", 1);
    assert!(digest(&with_script_sig).contains("non-empty scriptSig"));
    assert!(digest(&format!("{VECTOR_TX}00")).contains("trailing bytes"));
}
