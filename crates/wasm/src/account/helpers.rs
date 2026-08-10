//! Internal parsing/conversion helpers shared by the account modules.

use crate::error::{WasmError, WasmResult};
use crate::types::{WasmCiphertext, WasmDecryptedPoint};
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

/// Parse a hex string to Felt.
pub(super) fn parse_felt(hex: &str) -> WasmResult<Felt> {
    Felt::from_hex(hex).map_err(|e| WasmError::SerializationError(e.to_string()))
}

pub(super) fn parse_u128_decimal(value: &str) -> WasmResult<u128> {
    value
        .parse()
        .map_err(|_| WasmError::SerializationError("invalid decimal amount".to_string()))
}

pub(super) fn parse_ciphertext(
    ciphertext: &WasmCiphertext,
) -> Result<krusty_kms_common::ElGamalCiphertext, JsValue> {
    let l_x = parse_felt(&ciphertext.l_x)?;
    let l_y = parse_felt(&ciphertext.l_y)?;
    let r_x = parse_felt(&ciphertext.r_x)?;
    let r_y = parse_felt(&ciphertext.r_y)?;

    let l = starknet_types_core::curve::ProjectivePoint::from_affine(l_x, l_y)
        .map_err(|e| JsValue::from_str(&format!("Invalid L point: {e:?}")))?;
    let r = starknet_types_core::curve::ProjectivePoint::from_affine(r_x, r_y)
        .map_err(|e| JsValue::from_str(&format!("Invalid R point: {e:?}")))?;

    Ok(krusty_kms_common::ElGamalCiphertext { l, r })
}

pub(super) fn decrypted_point_to_wasm(
    point: starknet_types_core::curve::ProjectivePoint,
) -> WasmDecryptedPoint {
    match point.to_affine() {
        Ok(affine) => WasmDecryptedPoint {
            is_identity: false,
            x: Some(format!("{:#x}", affine.x())),
            y: Some(format!("{:#x}", affine.y())),
        },
        Err(_) => WasmDecryptedPoint {
            is_identity: true,
            x: None,
            y: None,
        },
    }
}
