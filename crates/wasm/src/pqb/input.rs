//! Validate values before JS numeric narrowing or bulk transaction copies.
use krusty_kms::pqb::PqbNetwork;
use wasm_bindgen::prelude::*;

pub(super) fn error(e: impl core::fmt::Display) -> JsValue {
    js_sys::Error::new(&e.to_string()).into()
}
pub(super) fn network(name: &str) -> Result<PqbNetwork, JsValue> {
    match name {
        "main" => Ok(PqbNetwork::Mainnet),
        "testnet4" => Ok(PqbNetwork::Testnet4),
        "regtest" => Ok(PqbNetwork::Regtest),
        _ => Err(error("PQB network must be main, testnet4 or regtest")),
    }
}
fn array(value: &JsValue, min: u32, max: u32) -> Result<&js_sys::Array, JsValue> {
    let a = value
        .dyn_ref::<js_sys::Array>()
        .ok_or_else(|| error("Expected a plain index array"))?;
    if !(min..=max).contains(&a.length()) {
        return Err(error("Invalid index array length"));
    }
    Ok(a)
}
pub(super) fn indices<const N: usize>(value: &JsValue) -> Result<[u8; N], JsValue> {
    let a = array(value, N as u32, N as u32)?;
    let mut out = [0; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = crate::numeric_input::u8(a.get(i as u32), "PQB selection")?;
    }
    Ok(out)
}
pub(super) fn deposit_indices(value: &JsValue) -> Result<Vec<u32>, JsValue> {
    // A PSBT cannot contain more than 100,000 inputs (the Rust parser's limit).
    let a = array(value, 1, 100_000)?;
    (0..a.length())
        .map(|i| crate::numeric_input::u32(a.get(i), "deposit input index"))
        .collect()
}
pub(super) fn hash(text: &str) -> Result<[u8; 32], JsValue> {
    if text.len() != 64 || !canonical_hex(text) {
        return Err(error("Expected 64 lowercase hex script hash characters"));
    }
    let mut out = [0; 32];
    hex::decode_to_slice(text, &mut out).map_err(error)?;
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
