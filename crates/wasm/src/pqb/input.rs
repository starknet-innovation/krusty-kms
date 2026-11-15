//! Validate values before JS numeric narrowing or bulk transaction copies.
use krusty_kms::pqb::PqbNetwork;
use wasm_bindgen::prelude::*;

pub(super) fn error(e: impl core::fmt::Display) -> JsValue {
    js_sys::Error::new(&e.to_string()).into()
}
pub(super) fn network(name: &js_sys::JsString) -> Result<PqbNetwork, JsValue> {
    if !name.is_string() || name.length() > 8 {
        return Err(error("PQB network must be main, testnet4 or regtest"));
    }
    match String::from(name).as_str() {
        "main" => Ok(PqbNetwork::Mainnet),
        "testnet4" => Ok(PqbNetwork::Testnet4),
        "regtest" => Ok(PqbNetwork::Regtest),
        _ => Err(error("PQB network must be main, testnet4 or regtest")),
    }
}
fn array(value: &JsValue, min: u32, max: u32) -> Result<(&js_sys::Array, u32), JsValue> {
    let a = value
        .dyn_ref::<js_sys::Array>()
        .ok_or_else(|| error("Expected a plain index array"))?;
    let len = a.length();
    if !(min..=max).contains(&len) {
        return Err(error("Invalid index array length"));
    }
    Ok((a, len))
}
pub(super) fn indices<const N: usize>(value: &JsValue) -> Result<[u8; N], JsValue> {
    let (a, _) = array(value, N as u32, N as u32)?;
    let mut out = [0; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = crate::numeric_input::u8(a.get(i as u32), "PQB selection")?;
    }
    Ok(out)
}
pub(super) fn deposit_indices(value: &JsValue) -> Result<Vec<u32>, JsValue> {
    // A PSBT cannot contain more than 100,000 inputs (the Rust parser's limit).
    let (a, len) = array(value, 1, 100_000)?;
    (0..len)
        .map(|i| crate::numeric_input::u32(a.get(i), "deposit input index"))
        .collect()
}
pub(super) fn hash(text: &js_sys::JsString) -> Result<[u8; 32], JsValue> {
    if !text.is_string() || text.length() != 64 {
        return Err(error("Expected 64 lowercase hex script hash characters"));
    }
    let text = String::from(text);
    if !canonical_hex(&text) {
        return Err(error("Expected 64 lowercase hex script hash characters"));
    }
    let mut out = [0; 32];
    hex::decode_to_slice(&text, &mut out).map_err(error)?;
    Ok(out)
}
fn canonical_hex(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn transaction(text: &js_sys::JsString) -> Result<Vec<u8>, JsValue> {
    if !text.is_string() || text.length() > 100_000 {
        return Err(error(
            "Expected transaction hex of at most 100,000 characters",
        ));
    }
    let text = String::from(text);
    if !canonical_hex(&text) {
        return Err(error("Expected lowercase unprefixed transaction hex"));
    }
    hex::decode(text).map_err(error)
}

/// Match the native parser's encoded 4 MiB limit before copying text out of JS.
pub(super) fn psbt(text: &js_sys::JsString) -> Result<String, JsValue> {
    const MAX_BASE64_CHARS: u32 = (4 * 1024 * 1024_u32).div_ceil(3) * 4;
    if !text.is_string() || text.length() > MAX_BASE64_CHARS {
        return Err(error(format!(
            "Expected PSBT base64 of at most {MAX_BASE64_CHARS} characters"
        )));
    }
    Ok(String::from(text))
}
