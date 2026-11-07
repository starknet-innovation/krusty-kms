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

    crate::felt_input::parse_felt(trimmed).map_err(|e| JsValue::from_str(&e))
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
///   [{ "contractAddress": "0x123", "entrypoint": "transfer", "calldata": ["0x1", "1000"] }]
///   ```
///
/// # Errors
/// Returns `JsValue` (string) on invalid JSON or felt input.
#[wasm_bindgen(js_name = "compileCalls")]
pub fn compile_calls(calls_json: &str) -> Result<Vec<String>, JsValue> {
    let calls: Vec<Call> = serde_json::from_str(calls_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid calls JSON: {e}")))?;

    let mut call_array: Vec<Felt> = Vec::new();
    let mut all_calldata: Vec<Felt> = Vec::new();

    for call in &calls {
        let to = crate::felt_input::parse_felt(&call.contract_address)
            .map_err(|e| JsValue::from_str(&format!("Invalid address: {e}")))?;
        let selector = starknet_keccak(call.entrypoint.as_bytes());
        let data = match &call.calldata {
            Some(cd) => cd
                .iter()
                .map(|s| {
                    crate::felt_input::parse_felt(s)
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
/// * `felt_hex` — Decimal or prefixed hexadecimal representation of the felt.
///
/// # Returns
/// The decoded string.
#[wasm_bindgen(js_name = "decodeShortString")]
pub fn decode_short_string(felt_hex: &str) -> Result<String, JsValue> {
    let felt = crate::felt_input::parse_felt(felt_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid felt: {e}")))?;
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
mod tests;
