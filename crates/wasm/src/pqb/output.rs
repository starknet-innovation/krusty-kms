//! Public serialization and selected-only disclosure copies.
use super::input::error;
use krusty_kms::pqb::{PqbDeposit, PqbDisclosure, PqbPublicMaterial, PqbRequest};
use serde_json::json;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export interface PqbPublicMenu {
  r: string;
  commitments: string[];
  recoveryPoints: string[][];
}
export interface PqbPublicMaterial {
  script: string;
  scriptSha256: string;
  commitments: string[];
  cosigPublicKey: string;
  menus: [PqbPublicMenu, PqbPublicMenu, PqbPublicMenu];
}
export interface PqbDeposit {
  address: string;
  scriptPubkey: string;
  publicKey: string;
}
export interface PqbRequestInfo {
  digest: string;
  cosigSighash: string;
  stageSighashes: [string, string, string];
}
export interface PqbDisclosure {
  round0: string[];
  round1: string[];
  menus: [string, string, string];
  cosignature: string;
}
"#;
fn public_value(value: serde_json::Value) -> Result<JsValue, JsValue> {
    // JSON.parse returns plain JS objects, including nested menu objects.
    js_sys::JSON::parse(&value.to_string())
}
pub(super) fn public(p: &PqbPublicMaterial) -> Result<JsValue, JsValue> {
    let menus: Vec<_> = p
        .menus
        .iter()
        .map(|m| {
            json!({
                "r": hex::encode(m.r),
                "commitments": m.commitments.iter().map(hex::encode).collect::<Vec<_>>(),
                "recoveryPoints": m.recovery_points.iter().map(|points|
                    points.iter().map(hex::encode).collect::<Vec<_>>()
                ).collect::<Vec<_>>(),
            })
        })
        .collect();
    public_value(json!({
        "script": hex::encode(&p.script), "scriptSha256": hex::encode(p.script_sha256),
        "commitments": p.commitments.iter().map(hex::encode).collect::<Vec<_>>(),
        "cosigPublicKey": hex::encode(p.cosig_public_key), "menus": menus,
    }))
}
pub(super) fn deposit(p: &PqbDeposit) -> Result<JsValue, JsValue> {
    public_value(
        json!({"address": p.address, "scriptPubkey": hex::encode(&p.script_pubkey),
        "publicKey": hex::encode(p.public_key)}),
    )
}
pub(super) fn request(r: &PqbRequest) -> Result<JsValue, JsValue> {
    public_value(
        json!({"digest": hex::encode(r.digest()), "cosigSighash": hex::encode(r.cosig_sighash()),
        "stageSighashes": r.stage_sighashes().iter().map(hex::encode).collect::<Vec<_>>()}),
    )
}
fn secret_hex(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let mut encoded = Zeroizing::new(vec![0; bytes.len() * 2]);
    hex::encode_to_slice(bytes, encoded.as_mut_slice()).map_err(error)?;
    Ok(JsValue::from_str(
        core::str::from_utf8(&encoded).map_err(error)?,
    ))
}
fn secret_array<'a>(bytes: impl IntoIterator<Item = &'a [u8]>) -> Result<JsValue, JsValue> {
    let array = js_sys::Array::new();
    for b in bytes {
        array.push(&secret_hex(b)?);
    }
    Ok(array.into())
}
pub(super) fn disclosure(d: &PqbDisclosure) -> Result<JsValue, JsValue> {
    let object = js_sys::Object::new();
    for (key, value) in [
        (
            "round0",
            secret_array(d.round0().iter().map(|b| b.as_slice()))?,
        ),
        (
            "round1",
            secret_array(d.round1().iter().map(|b| b.as_slice()))?,
        ),
        ("menus", secret_array(d.menus().iter().map(Vec::as_slice))?),
        ("cosignature", secret_hex(d.cosignature())?),
    ] {
        js_sys::Reflect::set(&object, &JsValue::from_str(key), &value)?;
    }
    Ok(object.into())
}
