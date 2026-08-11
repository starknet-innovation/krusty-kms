//! WASM bindings for general-purpose utility functions.
//!
//! Provides key grinding, random byte generation, and felt validation
//! accessible from JavaScript/TypeScript.

use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

/// Grind a 32-byte seed into a valid Stark private key.
///
/// Implements the standard Stark key grinding algorithm that ensures
/// the output is a valid scalar on the Stark curve (less than the curve order).
///
/// # Arguments
/// * `seed_hex` - Hex-encoded 32-byte seed (with or without `0x` prefix)
///
/// # Returns
/// The ground key as a hex string
#[wasm_bindgen(js_name = "grindKey")]
pub fn grind_key(seed_hex: &str) -> Result<String, JsValue> {
    let stripped = seed_hex
        .strip_prefix("0x")
        .or_else(|| seed_hex.strip_prefix("0X"))
        .unwrap_or(seed_hex);

    let bytes =
        hex::decode(stripped).map_err(|e| JsValue::from_str(&format!("Invalid hex seed: {e}")))?;

    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "Seed must be exactly 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);

    let felt = krusty_kms::grind_key(&arr)
        .map_err(|e| JsValue::from_str(&format!("grind_key failed: {e}")))?;

    Ok(format!("{:#x}", felt))
}

/// Generate random bytes and return them as a hex string.
///
/// Uses a cryptographically secure random number generator.
///
/// # Arguments
/// * `length` - Number of random bytes to generate (maximum 1024 — this API
///   exists for keys/nonces/salts, and an unbounded caller-supplied length is
///   an allocation-DoS vector)
///
/// # Returns
/// Hex-encoded bytes with `0x` prefix
#[wasm_bindgen(js_name = "randomBytesHex")]
pub fn random_bytes_hex(length: usize) -> Result<String, JsValue> {
    use rand_core::TryRng;

    /// Largest byte count this convenience API will generate.
    const MAX_RANDOM_BYTES: usize = 1024;

    if length > MAX_RANDOM_BYTES {
        return Err(JsValue::from_str(&format!(
            "length {length} exceeds maximum {MAX_RANDOM_BYTES}"
        )));
    }

    let mut bytes = vec![0u8; length];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes[..])
        .map_err(|e| JsValue::from_str(&format!("RNG failed: {e}")))?;

    Ok(format!("0x{}", hex::encode(&bytes)))
}

/// Check whether a hex string is a valid Stark field element.
///
/// # Arguments
/// * `hex_str` - Hex string to validate (with or without `0x` prefix)
///
/// # Returns
/// `true` if the string parses as a valid felt, `false` otherwise
#[wasm_bindgen(js_name = "isValidFelt")]
pub fn is_valid_felt(hex_str: &str) -> bool {
    Felt::from_hex(hex_str).is_ok()
}

/// Check whether a hex string is a valid Stark private key.
///
/// A valid private key must parse as a felt, must not be zero, and must be
/// strictly below the Stark curve order `n`. Values in `[n, p)` parse as
/// felts but silently reduce mod `n` when used for signing — i.e. they alias
/// to a *different* key — so they are rejected here.
///
/// # Arguments
/// * `hex_str` - Hex string to validate (with or without `0x` prefix)
///
/// # Returns
/// `true` if the string is a valid in-range private key, `false` otherwise
#[wasm_bindgen(js_name = "isValidStarkPrivateKey")]
pub fn is_valid_stark_private_key(hex_str: &str) -> bool {
    /// Stark curve order (the order of the generator point).
    const CURVE_ORDER_HEX: &str =
        "0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";
    let curve_order = Felt::from_hex_unchecked(CURVE_ORDER_HEX);
    match Felt::from_hex(hex_str) {
        Ok(felt) => felt != Felt::ZERO && felt < curve_order,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_grind_key() {
        // Known 32-byte seed
        let seed = "86F3E7293141F20A8BAFF320E8EE4ACCB9D4A4BF2B4D295E8CEE784DB46E0519";
        let result = grind_key(seed).unwrap();
        assert!(result.starts_with("0x"));
        assert_ne!(result, "0x0");
        // Output should be a valid felt
        assert!(Felt::from_hex(&result).is_ok());
    }

    #[wasm_bindgen_test]
    fn test_random_bytes_hex() {
        let result = random_bytes_hex(16).unwrap();
        assert!(result.starts_with("0x"));
        // 16 bytes = 32 hex chars + "0x" prefix = 34 chars
        assert_eq!(result.len(), 34);

        // Two calls should produce different results (with overwhelming probability)
        let result2 = random_bytes_hex(16).unwrap();
        assert_ne!(result, result2);
    }

    #[wasm_bindgen_test]
    fn test_is_valid_felt() {
        assert!(is_valid_felt("0x1"));
        assert!(!is_valid_felt("not_hex"));
    }

    #[wasm_bindgen_test]
    fn test_is_valid_stark_private_key() {
        assert!(!is_valid_stark_private_key("0x0"));
        assert!(is_valid_stark_private_key("0x1"));
    }
}
