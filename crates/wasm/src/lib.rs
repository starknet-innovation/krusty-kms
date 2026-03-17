//! TONGO WASM SDK
//!
//! WebAssembly bindings for the TONGO confidential transaction protocol.
//! This crate provides JavaScript/TypeScript-accessible APIs for:
//!
//! - Account management (creation, key derivation, state tracking)
//! - Proof generation (fund, transfer, rollover, withdraw, ragequit)
//! - Cryptographic utilities (encryption, decryption, key operations)
//!
//! # Usage from JavaScript/TypeScript
//!
//! ```typescript
//! import init, {
//!   WasmAccount,
//!   generateMnemonic,
//!   validateMnemonic,
//!   generateFundProof,
//!   generateTransferProof,
//! } from 'krusty-kms-wasm';
//!
//! // Initialize WASM module
//! await init();
//!
//! // Generate a new mnemonic
//! const mnemonic = generateMnemonic(12);
//!
//! // Create account from mnemonic
//! const account = WasmAccount.fromMnemonic(
//!   mnemonic,
//!   0, // address index
//!   0, // account index
//!   '0x1234...', // contract address
//!   null // optional passphrase
//! );
//!
//! // Generate proofs for transactions
//! const fundParams = new WasmFundParams(...);
//! const fundProof = generateFundProof(account, fundParams);
//! ```
//!
//! # Security Considerations
//!
//! - Private keys are never exposed to JavaScript except through explicit export
//! - All cryptographic operations happen in WASM (Rust)
//! - TONGO accounts use a single account key for proof generation and decryption
//! - Proofs are generated client-side, maintaining privacy

#![allow(clippy::new_without_default)]

pub mod account;
pub mod error;
pub mod proof;
pub mod types;

use wasm_bindgen::prelude::*;

// Re-export main types for convenience
pub use account::{
    derive_keypair, derive_nostr_keypair, generate_mnemonic, get_nostr_coin_type,
    validate_mnemonic, WasmAccount,
};
pub use error::WasmError;
pub use proof::{
    generate_fund_proof, generate_ragequit_proof, generate_rollover_proof, generate_transfer_proof,
    generate_withdraw_proof, WasmFundParams, WasmFundProofResult, WasmRagequitParams,
    WasmRagequitProofResult, WasmRolloverParams, WasmRolloverProofResult, WasmTransferParams,
    WasmTransferProofResult, WasmWithdrawParams, WasmWithdrawProofResult,
};
pub use types::{
    WasmAccountState, WasmCiphertext, WasmKeypair, WasmNostrKeypair, WasmPoint, WasmTxType,
};

/// Initialize the WASM module.
///
/// Sets up panic hook for better error messages in console.
/// Call this before using any other functions.
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Get the SDK version.
#[wasm_bindgen(js_name = "getVersion")]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get build information.
#[wasm_bindgen(js_name = "getBuildInfo")]
pub fn get_build_info() -> JsValue {
    use serde_json::json;

    let info = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": env!("CARGO_PKG_NAME"),
        "target": "wasm32-unknown-unknown",
        "features": {
            "console_error_panic_hook": cfg!(feature = "console_error_panic_hook"),
        }
    });

    serde_wasm_bindgen::to_value(&info).unwrap_or(JsValue::NULL)
}

// ============================================================================
// Cryptographic Utilities
// ============================================================================

/// Compute a Poseidon hash of the given inputs.
///
/// # Arguments
/// * `inputs` - Array of hex strings (felt values)
///
/// # Returns
/// The hash as a hex string
#[wasm_bindgen(js_name = "poseidonHash")]
pub fn poseidon_hash(inputs: Vec<String>) -> Result<String, JsValue> {
    use krusty_kms_crypto::poseidon_hash_many;
    use starknet_types_core::felt::Felt;

    let felts: Vec<Felt> = inputs
        .iter()
        .map(|s| {
            Felt::from_hex(s).map_err(|e| JsValue::from_str(&format!("Invalid hex input: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let hash = poseidon_hash_many(&felts);
    Ok(format!("{:#x}", hash))
}

/// Multiply a point by a scalar.
///
/// # Arguments
/// * `scalar` - Scalar value (hex string)
/// * `point_x` - Point X coordinate (hex string)
/// * `point_y` - Point Y coordinate (hex string)
///
/// # Returns
/// Resulting point as {x, y} object
#[wasm_bindgen(js_name = "scalarMul")]
pub fn scalar_mul(scalar: &str, point_x: &str, point_y: &str) -> Result<types::WasmPoint, JsValue> {
    use krusty_kms_crypto::StarkCurve;
    use starknet_types_core::curve::ProjectivePoint;
    use starknet_types_core::felt::Felt;

    let s =
        Felt::from_hex(scalar).map_err(|e| JsValue::from_str(&format!("Invalid scalar: {e}")))?;
    let px =
        Felt::from_hex(point_x).map_err(|e| JsValue::from_str(&format!("Invalid point X: {e}")))?;
    let py =
        Felt::from_hex(point_y).map_err(|e| JsValue::from_str(&format!("Invalid point Y: {e}")))?;

    let point = ProjectivePoint::from_affine(px, py)
        .map_err(|e| JsValue::from_str(&format!("Invalid point: {e:?}")))?;

    let result = StarkCurve::mul(&s, Some(&point));
    let affine = result
        .to_affine()
        .map_err(|_| JsValue::from_str("Result is point at infinity"))?;

    Ok(types::WasmPoint {
        x: format!("{:#x}", affine.x()),
        y: format!("{:#x}", affine.y()),
    })
}

/// Multiply the generator point by a scalar.
///
/// # Arguments
/// * `scalar` - Scalar value (hex string)
///
/// # Returns
/// Resulting point as {x, y} object
#[wasm_bindgen(js_name = "scalarMulGenerator")]
pub fn scalar_mul_generator(scalar: &str) -> Result<types::WasmPoint, JsValue> {
    use krusty_kms_crypto::StarkCurve;
    use starknet_types_core::felt::Felt;

    let s =
        Felt::from_hex(scalar).map_err(|e| JsValue::from_str(&format!("Invalid scalar: {e}")))?;

    let result = StarkCurve::mul_generator(&s);
    let affine = result
        .to_affine()
        .map_err(|_| JsValue::from_str("Result is point at infinity"))?;

    Ok(types::WasmPoint {
        x: format!("{:#x}", affine.x()),
        y: format!("{:#x}", affine.y()),
    })
}

/// Get the Stark curve generator point.
#[wasm_bindgen(js_name = "getGenerator")]
pub fn get_generator() -> types::WasmPoint {
    use krusty_kms_crypto::StarkCurve;

    let g = StarkCurve::generator();
    let affine = g.to_affine().expect("Generator is never at infinity");

    types::WasmPoint {
        x: format!("{:#x}", affine.x()),
        y: format!("{:#x}", affine.y()),
    }
}

/// Add two points on the Stark curve.
#[wasm_bindgen(js_name = "pointAdd")]
pub fn point_add(
    p1_x: &str,
    p1_y: &str,
    p2_x: &str,
    p2_y: &str,
) -> Result<types::WasmPoint, JsValue> {
    use starknet_types_core::curve::ProjectivePoint;
    use starknet_types_core::felt::Felt;

    let p1x = Felt::from_hex(p1_x).map_err(|e| JsValue::from_str(&format!("Invalid P1 X: {e}")))?;
    let p1y = Felt::from_hex(p1_y).map_err(|e| JsValue::from_str(&format!("Invalid P1 Y: {e}")))?;
    let p2x = Felt::from_hex(p2_x).map_err(|e| JsValue::from_str(&format!("Invalid P2 X: {e}")))?;
    let p2y = Felt::from_hex(p2_y).map_err(|e| JsValue::from_str(&format!("Invalid P2 Y: {e}")))?;

    let p1 = ProjectivePoint::from_affine(p1x, p1y)
        .map_err(|e| JsValue::from_str(&format!("Invalid P1: {e:?}")))?;
    let p2 = ProjectivePoint::from_affine(p2x, p2y)
        .map_err(|e| JsValue::from_str(&format!("Invalid P2: {e:?}")))?;

    let result = &p1 + &p2;
    let affine = result
        .to_affine()
        .map_err(|_| JsValue::from_str("Result is point at infinity"))?;

    Ok(types::WasmPoint {
        x: format!("{:#x}", affine.x()),
        y: format!("{:#x}", affine.y()),
    })
}

/// Generate a random field element.
#[wasm_bindgen(js_name = "randomFelt")]
pub fn random_felt() -> String {
    use rand::Rng;
    use starknet_types_core::felt::Felt;

    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    let felt = Felt::from_bytes_be(&bytes);
    format!("{:#x}", felt)
}

// ============================================================================
// Serialization Utilities
// ============================================================================

/// Serialize a public key point to the standard hex format.
///
/// # Arguments
/// * `x` - X coordinate (hex string)
/// * `y` - Y coordinate (hex string)
///
/// # Returns
/// Concatenated "0x{x}{y}" format used by TONGO protocol
#[wasm_bindgen(js_name = "serializePublicKey")]
pub fn serialize_public_key(x: &str, y: &str) -> String {
    use starknet_types_core::felt::Felt;

    let x_felt = Felt::from_hex(x).unwrap_or(Felt::ZERO);
    let y_felt = Felt::from_hex(y).unwrap_or(Felt::ZERO);

    krusty_kms_common::utils::serialize_public_key_hex(&x_felt, &y_felt)
}

/// Deserialize a public key from hex format to (x, y) coordinates.
///
/// # Arguments
/// * `hex` - Public key in "0x{x}{y}" format (128 hex chars after 0x)
///
/// # Returns
/// Object with x and y properties
#[wasm_bindgen(js_name = "deserializePublicKey")]
pub fn deserialize_public_key(hex: &str) -> Result<types::WasmPoint, JsValue> {
    use starknet_types_core::felt::Felt;

    let hex = hex.trim();

    // Validate format
    if !hex.starts_with("0x") && !hex.starts_with("0X") {
        return Err(JsValue::from_str("Public key must start with 0x"));
    }

    let hex_data = &hex[2..];
    if hex_data.len() != 128 {
        return Err(JsValue::from_str(
            "Public key must be 128 hex characters after 0x (64 for x, 64 for y)",
        ));
    }

    let x_hex = format!("0x{}", &hex_data[..64]);
    let y_hex = format!("0x{}", &hex_data[64..]);

    let x = Felt::from_hex(&x_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid X coordinate: {e}")))?;
    let y = Felt::from_hex(&y_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid Y coordinate: {e}")))?;

    Ok(types::WasmPoint {
        x: format!("{:#x}", x),
        y: format!("{:#x}", y),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_poseidon_hash() {
        let inputs = vec!["0x1".to_string(), "0x2".to_string()];
        let result = poseidon_hash(inputs);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(hash.starts_with("0x"));
    }

    #[wasm_bindgen_test]
    fn test_generator() {
        let g = get_generator();
        assert!(g.x.starts_with("0x"));
        assert!(g.y.starts_with("0x"));
    }

    #[wasm_bindgen_test]
    fn test_scalar_mul_generator() {
        let result = scalar_mul_generator("0x1");
        assert!(result.is_ok());
        let point = result.unwrap();
        // g^1 should equal g
        let g = get_generator();
        assert_eq!(point.x, g.x);
        assert_eq!(point.y, g.y);
    }

    #[wasm_bindgen_test]
    fn test_point_add() {
        let g = get_generator();
        let result = point_add(&g.x, &g.y, &g.x, &g.y);
        assert!(result.is_ok());
        // g + g should equal 2g
        let two_g = scalar_mul_generator("0x2").unwrap();
        let added = result.unwrap();
        assert_eq!(added.x, two_g.x);
        assert_eq!(added.y, two_g.y);
    }

    #[wasm_bindgen_test]
    fn test_random_felt() {
        let r1 = random_felt();
        let r2 = random_felt();
        assert!(r1.starts_with("0x"));
        assert!(r2.starts_with("0x"));
        // Should be different (with overwhelming probability)
        assert_ne!(r1, r2);
    }

    #[wasm_bindgen_test]
    fn test_serialize_deserialize_public_key() {
        let g = get_generator();
        let serialized = serialize_public_key(&g.x, &g.y);
        let deserialized = deserialize_public_key(&serialized).unwrap();
        assert_eq!(deserialized.x, g.x);
        assert_eq!(deserialized.y, g.y);
    }
}
