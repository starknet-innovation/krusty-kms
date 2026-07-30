//! WASM bindings for STRK20 privacy-pool key derivation.

use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

/// Derive the STRK20 viewing key from a Stark private key and chain/pool scope.
///
/// This mirrors the Starknet Privacy SDK demo's deterministic ECDSA + Poseidon
/// reference and returns a canonical key in `[1, n/2]`.
///
/// # Arguments
/// * `private_key` - The Stark private key as a hex string.
/// * `chain_id` - The active Starknet chain id as a canonical hex string.
/// * `pool_address` - The active privacy pool address as a canonical hex string.
///
/// # Returns
/// The viewing key as a `0x`-prefixed hex string.
#[wasm_bindgen(js_name = "deriveStrk20ViewingKey")]
pub fn derive_strk20_viewing_key(
    private_key: &str,
    chain_id: &str,
    pool_address: &str,
) -> Result<String, JsValue> {
    let pk = Felt::from_hex(private_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid private key hex: {e}")))?;
    let viewing_key = krusty_kms::strk20::derive_strk20_viewing_key(&pk, chain_id, pool_address)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(format!("{:#x}", viewing_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn derive_viewing_key_known_answer() {
        // Anchored to starknet@10.0.2 (see krusty_kms::strk20 tests).
        assert_eq!(
            derive_strk20_viewing_key("0x1", "0x534e5f5345504f4c4941", "0x123").unwrap(),
            "0x27cae3ff78010cbec0f29c0c94420cc4d41ca326d664e510cca4dcc6082beb3",
        );
    }

    #[wasm_bindgen_test]
    fn derive_viewing_key_rejects_bad_hex() {
        assert!(derive_strk20_viewing_key("not-hex", "0x1", "0x2").is_err());
        assert!(derive_strk20_viewing_key("0x1", "0x01", "0x2").is_err());
    }
}
