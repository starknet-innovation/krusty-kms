use super::*;
use wasm_bindgen_test::*;

// -- compileCalls -------------------------------------------------------

#[wasm_bindgen_test]
fn test_compile_calls_single() {
    let json = r#"[{
        "contractAddress": "0xdead",
        "entrypoint": "transfer",
        "calldata": ["0x1", "0x2"]
    }]"#;

    let result = compile_calls(json).unwrap();

    // call_array_len = 1
    assert_eq!(result[0], "0x1");
    // to
    assert_eq!(result[1], "0xdead");
    // selector — starknet_keccak("transfer")
    let expected_selector = starknet_keccak(b"transfer");
    assert_eq!(result[2], format!("{:#x}", expected_selector));
    // data_offset = 0
    assert_eq!(result[3], "0x0");
    // data_len = 2
    assert_eq!(result[4], "0x2");
    // total_calldata_len = 2
    assert_eq!(result[5], "0x2");
    // calldata values
    assert_eq!(result[6], "0x1");
    assert_eq!(result[7], "0x2");
    // total length: 1 + 4 + 1 + 2 = 8
    assert_eq!(result.len(), 8);
}

#[wasm_bindgen_test]
fn compile_calls_treats_unprefixed_amount_and_address_as_decimal() {
    let json = r#"[{
        "contractAddress": "1234",
        "entrypoint": "transfer",
        "calldata": ["0x1234", "1000000000000000000", "0"]
    }]"#;
    let result = compile_calls(json).unwrap();
    assert_eq!(result[1], "0x4d2");
    assert_eq!(result[6], "0x1234");
    assert_eq!(result[7], "0xde0b6b3a7640000");
    assert_eq!(result[8], "0x0");
    assert_eq!(result[7], encode_felt("1000000000000000000").unwrap());
}

#[wasm_bindgen_test]
fn compile_calls_rejects_unprefixed_hex_text() {
    let json = r#"[{"contractAddress":"abcd","entrypoint":"transfer"}]"#;
    assert!(compile_calls(json).is_err());
}

#[wasm_bindgen_test]
fn test_compile_calls_multiple() {
    let json = r#"[
        {
            "contractAddress": "0xaaa",
            "entrypoint": "approve",
            "calldata": ["0x10", "0x20", "0x30"]
        },
        {
            "contractAddress": "0xbbb",
            "entrypoint": "transfer",
            "calldata": ["0x40"]
        }
    ]"#;

    let result = compile_calls(json).unwrap();

    // call_array_len = 2
    assert_eq!(result[0], "0x2");

    // First call: to, selector, offset=0, len=3
    assert_eq!(result[1], "0xaaa");
    assert_eq!(result[3], "0x0"); // offset
    assert_eq!(result[4], "0x3"); // len

    // Second call: to, selector, offset=3, len=1
    assert_eq!(result[5], "0xbbb");
    assert_eq!(result[7], "0x3"); // offset
    assert_eq!(result[8], "0x1"); // len

    // total_calldata_len = 4
    assert_eq!(result[9], "0x4");

    // Calldata: 0x10, 0x20, 0x30, 0x40
    assert_eq!(result[10], "0x10");
    assert_eq!(result[11], "0x20");
    assert_eq!(result[12], "0x30");
    assert_eq!(result[13], "0x40");

    // total length: 1 + 8 (2*4) + 1 + 4 = 14
    assert_eq!(result.len(), 14);
}

#[wasm_bindgen_test]
fn test_compile_calls_empty_calldata() {
    let json = r#"[{
        "contractAddress": "0x123",
        "entrypoint": "get_balance"
    }]"#;

    let result = compile_calls(json).unwrap();

    // call_array_len = 1
    assert_eq!(result[0], "0x1");
    // to
    assert_eq!(result[1], "0x123");
    // data_offset = 0
    assert_eq!(result[3], "0x0");
    // data_len = 0
    assert_eq!(result[4], "0x0");
    // total_calldata_len = 0
    assert_eq!(result[5], "0x0");
    // total length: 1 + 4 + 1 = 6
    assert_eq!(result.len(), 6);
}

// -- encodeFelt ---------------------------------------------------------

#[wasm_bindgen_test]
fn test_encode_felt_hex() {
    assert_eq!(encode_felt("0x1").unwrap(), "0x1");
}

#[wasm_bindgen_test]
fn test_encode_felt_decimal() {
    assert_eq!(encode_felt("42").unwrap(), "0x2a");
}

#[wasm_bindgen_test]
fn test_encode_felt_bool() {
    assert_eq!(encode_felt("true").unwrap(), "0x1");
    assert_eq!(encode_felt("false").unwrap(), "0x0");
}

// -- encodeShortString / decodeShortString ------------------------------

#[wasm_bindgen_test]
fn test_encode_short_string() {
    let hex = encode_short_string("hello").unwrap();
    // "hello" = 0x68656c6c6f
    assert_eq!(hex, "0x68656c6c6f");
}

#[wasm_bindgen_test]
fn test_decode_short_string() {
    let hex = encode_short_string("hello").unwrap();
    let decoded = decode_short_string(&hex).unwrap();
    assert_eq!(decoded, "hello");
}

#[wasm_bindgen_test]
fn test_decode_short_string_round_trip() {
    let original = "starknet";
    let encoded = encode_short_string(original).unwrap();
    let decoded = decode_short_string(&encoded).unwrap();
    assert_eq!(decoded, original);
}
