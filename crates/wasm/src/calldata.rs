//! Calldata serialization utilities for Starknet transactions.
//!
//! Provides WASM-accessible helpers for compiling multicall arrays,
//! encoding/decoding felts, and working with Cairo short strings.

use serde::Deserialize;
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute the StarkNet keccak of `data` (Keccak-256 truncated to 250 bits).
fn starknet_keccak(data: &[u8]) -> Felt {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes[0] &= 0x03; // truncate to 250 bits
    Felt::from_bytes_be_slice(&bytes)
}

/// Encode a string as a Cairo short string (ASCII bytes -> big-endian Felt).
///
/// Mirrors `krusty_kms::encode_short_string` but kept local so the WASM
/// crate compiles independently of the KMS crate's visibility changes.
fn encode_short_string_felt(s: &str) -> Result<Felt, JsValue> {
    let bytes = s.as_bytes();
    if bytes.len() > 31 {
        return Err(JsValue::from_str(
            "Short string must be <= 31 ASCII characters",
        ));
    }
    if !s.is_ascii() {
        return Err(JsValue::from_str(
            "Short string must contain only ASCII characters",
        ));
    }
    Ok(Felt::from_bytes_be_slice(bytes))
}

/// Parse a string into a `Felt`, accepting hex, decimal, or boolean formats.
fn parse_felt_flexible(value: &str) -> Result<Felt, JsValue> {
    let trimmed = value.trim();

    // Boolean
    if trimmed == "true" {
        return Ok(Felt::ONE);
    }
    if trimmed == "false" {
        return Ok(Felt::ZERO);
    }

    // Hex
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        return Felt::from_hex(trimmed)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex: {e}")));
    }

    // Decimal — try u128 first (fast path), then fall back to Felt's own parser.
    if let Ok(num) = trimmed.parse::<u128>() {
        return Ok(Felt::from(num));
    }

    Felt::from_dec_str(trimmed)
        .map_err(|e| JsValue::from_str(&format!("Cannot encode as felt: {e}")))
}

// ---------------------------------------------------------------------------
// Deserialization types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Call {
    #[serde(alias = "contractAddress")]
    contract_address: String,
    entrypoint: String,
    calldata: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// WASM-exported functions
// ---------------------------------------------------------------------------

/// Compile an array of calls into the Starknet multicall `__execute__` ABI
/// format.
///
/// The returned vector of hex strings encodes:
/// ```text
/// [
///     call_array_len,
///     // per call: to, selector, data_offset, data_len
///     ...,
///     total_calldata_len,
///     // all calldata values concatenated
///     ...
/// ]
/// ```
///
/// # Arguments
/// * `calls_json` — a JSON array of `Call` objects:
///   ```json
///   [{ "contractAddress": "0x…", "entrypoint": "transfer", "calldata": ["0x1", "0x2"] }]
///   ```
///
/// # Errors
/// Returns `JsValue` (string) on invalid JSON, invalid hex, etc.
#[wasm_bindgen(js_name = "compileCalls")]
pub fn compile_calls(calls_json: &str) -> Result<Vec<String>, JsValue> {
    let calls: Vec<Call> = serde_json::from_str(calls_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid calls JSON: {e}")))?;

    let mut call_array: Vec<Felt> = Vec::new();
    let mut all_calldata: Vec<Felt> = Vec::new();

    for call in &calls {
        let to = Felt::from_hex(&call.contract_address)
            .map_err(|e| JsValue::from_str(&format!("Invalid address: {e}")))?;
        let selector = starknet_keccak(call.entrypoint.as_bytes());
        let data = match &call.calldata {
            Some(cd) => cd
                .iter()
                .map(|s| {
                    Felt::from_hex(s)
                        .map_err(|e| JsValue::from_str(&format!("Invalid calldata: {e}")))
                })
                .collect::<Result<Vec<_>, _>>()?,
            None => vec![],
        };
        let data_offset = Felt::from(all_calldata.len() as u64);
        let data_len = Felt::from(data.len() as u64);

        call_array.push(to);
        call_array.push(selector);
        call_array.push(data_offset);
        call_array.push(data_len);
        all_calldata.extend(data);
    }

    let mut result: Vec<Felt> = Vec::new();
    result.push(Felt::from(calls.len() as u64)); // call_array_len
    result.extend(call_array);
    result.push(Felt::from(all_calldata.len() as u64)); // calldata_len
    result.extend(all_calldata);

    Ok(result.iter().map(|f| format!("{:#x}", f)).collect())
}

/// Encode a value as a Felt hex string.
///
/// Supported input formats:
/// - Hex string (`"0x1a"`)
/// - Decimal number string (`"42"`)
/// - Boolean (`"true"` / `"false"`)
///
/// # Returns
/// The Felt as a `0x`-prefixed hex string.
#[wasm_bindgen(js_name = "encodeFelt")]
pub fn encode_felt(value: &str) -> Result<String, JsValue> {
    let felt = parse_felt_flexible(value)?;
    Ok(format!("{:#x}", felt))
}

/// Encode a short ASCII string (<=31 chars) as a Cairo short-string Felt.
///
/// # Returns
/// The Felt as a `0x`-prefixed hex string.
#[wasm_bindgen(js_name = "encodeShortString")]
pub fn encode_short_string(s: &str) -> Result<String, JsValue> {
    let felt = encode_short_string_felt(s)?;
    Ok(format!("{:#x}", felt))
}

/// Decode a Cairo short-string Felt back to a UTF-8 string.
///
/// # Arguments
/// * `felt_hex` — `0x`-prefixed hex representation of the felt.
///
/// # Returns
/// The decoded string.
#[wasm_bindgen(js_name = "decodeShortString")]
pub fn decode_short_string(felt_hex: &str) -> Result<String, JsValue> {
    let felt =
        Felt::from_hex(felt_hex).map_err(|e| JsValue::from_str(&format!("Invalid hex: {e}")))?;
    let bytes = felt.to_bytes_be();
    // Strip leading zero bytes
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let trimmed = &bytes[start..];
    String::from_utf8(trimmed.to_vec())
        .map_err(|e| JsValue::from_str(&format!("Not valid UTF-8: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
}
