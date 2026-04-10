//! Hashing primitives for Starknet: Pedersen, computeHashOnElements, and starknet_keccak.

use sha3::{Digest, Keccak256};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};
use wasm_bindgen::prelude::*;

/// Compute the Pedersen hash of two field elements.
///
/// # Arguments
/// * `a` - First element as a hex string
/// * `b` - Second element as a hex string
///
/// # Returns
/// The Pedersen hash as a hex string
#[wasm_bindgen(js_name = "pedersenHash")]
pub fn pedersen_hash(a: &str, b: &str) -> Result<String, JsValue> {
    let a = Felt::from_hex(a)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex input for a: {e}")))?;
    let b = Felt::from_hex(b)
        .map_err(|e| JsValue::from_str(&format!("Invalid hex input for b: {e}")))?;

    let hash = Pedersen::hash(&a, &b);
    Ok(format!("{:#x}", hash))
}

/// Compute `computeHashOnElements` over an array of field elements.
///
/// This chains Pedersen hashes starting from zero:
/// `pedersen(pedersen(pedersen(0, e0), e1), ..., len)`
///
/// # Arguments
/// * `felts` - Array of hex strings (felt values)
///
/// # Returns
/// The hash as a hex string
#[wasm_bindgen(js_name = "pedersenHashMany")]
pub fn pedersen_hash_many(felts: Vec<String>) -> Result<String, JsValue> {
    let felt_vec: Vec<Felt> = felts
        .iter()
        .map(|s| {
            Felt::from_hex(s).map_err(|e| JsValue::from_str(&format!("Invalid hex input: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let hash = krusty_kms::hash_elements(&felt_vec);
    Ok(format!("{:#x}", hash))
}

/// Compute Starknet keccak: Keccak-256 truncated to 250 bits.
///
/// # Arguments
/// * `data` - Input data (interpreted according to `encoding`)
/// * `encoding` - `"hex"` to hex-decode `data`, or `"utf8"` / `None` to use raw bytes
///
/// # Returns
/// The Starknet keccak hash as a hex string
#[wasm_bindgen(js_name = "starknetKeccak")]
pub fn starknet_keccak(data: &str, encoding: Option<String>) -> Result<String, JsValue> {
    let bytes = match encoding.as_deref() {
        Some("hex") => {
            let hex_str = data.strip_prefix("0x").unwrap_or(data);
            hex::decode(hex_str)
                .map_err(|e| JsValue::from_str(&format!("Invalid hex data: {e}")))?
        }
        Some("utf8") | None => data.as_bytes().to_vec(),
        Some(other) => {
            return Err(JsValue::from_str(&format!("Unsupported encoding: {other}")));
        }
    };

    let mut hasher = Keccak256::new();
    hasher.update(&bytes);
    let mut hash_bytes: [u8; 32] = hasher.finalize().into();

    // Mask top 6 bits to truncate to 250 bits for the Stark field
    hash_bytes[0] &= 0x03;

    let felt = Felt::from_bytes_be_slice(&hash_bytes);
    Ok(format!("{:#x}", felt))
}

/// Get a Starknet function selector from a function name.
///
/// Equivalent to `starknet_keccak(name.as_bytes())`.
///
/// # Arguments
/// * `name` - The function name (e.g. `"transfer"`)
///
/// # Returns
/// The selector as a hex string
#[wasm_bindgen(js_name = "getSelectorFromName")]
pub fn get_selector_from_name(name: &str) -> Result<String, JsValue> {
    starknet_keccak(name, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_pedersen_hash() {
        let result = pedersen_hash("0x1", "0x2");
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(hash.starts_with("0x"));
        // Verify deterministic and non-zero
        assert_ne!(hash, "0x0");
        // Same inputs should produce the same hash
        let result2 = pedersen_hash("0x1", "0x2").unwrap();
        assert_eq!(hash, result2);
    }

    #[wasm_bindgen_test]
    fn test_pedersen_hash_many() {
        let result = pedersen_hash_many(vec!["0x1".to_string()]);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(hash.starts_with("0x"));
        assert_ne!(hash, "0x0");

        // Multiple elements
        let result2 = pedersen_hash_many(vec![
            "0x1".to_string(),
            "0x2".to_string(),
            "0x3".to_string(),
        ]);
        assert!(result2.is_ok());
        let hash2 = result2.unwrap();
        assert!(hash2.starts_with("0x"));
        assert_ne!(hash2, "0x0");
        // Different input should produce different output
        assert_ne!(hash, hash2);
    }

    #[wasm_bindgen_test]
    fn test_starknet_keccak_utf8() {
        let result = starknet_keccak("transfer", None);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(hash.starts_with("0x"));
        assert_ne!(hash, "0x0");

        // Explicit "utf8" encoding should match None
        let result2 = starknet_keccak("transfer", Some("utf8".to_string()));
        assert!(result2.is_ok());
        assert_eq!(hash, result2.unwrap());
    }

    #[wasm_bindgen_test]
    fn test_starknet_keccak_hex() {
        // "transfer" in hex is "7472616e73666572"
        let hex_data = "7472616e73666572";
        let result = starknet_keccak(hex_data, Some("hex".to_string()));
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(hash.starts_with("0x"));

        // Should match the utf8 path with the same underlying bytes
        let utf8_result = starknet_keccak("transfer", None).unwrap();
        assert_eq!(hash, utf8_result);

        // With 0x prefix should also work
        let result_prefix = starknet_keccak("0x7472616e73666572", Some("hex".to_string())).unwrap();
        assert_eq!(hash, result_prefix);
    }

    #[wasm_bindgen_test]
    fn test_get_selector_from_name() {
        let selector = get_selector_from_name("transfer");
        assert!(selector.is_ok());
        let sel = selector.unwrap();

        // Should match starknet_keccak with utf8 encoding
        let keccak = starknet_keccak("transfer", None).unwrap();
        assert_eq!(sel, keccak);
    }
}
