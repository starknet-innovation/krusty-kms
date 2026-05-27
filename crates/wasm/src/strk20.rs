//! WASM bindings for STRK20 privacy-pool key derivation.

use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

/// Derive the STRK20 viewing key from a Stark private key.
///
/// The viewing key is `Pedersen(starknet_keccak(DOMAIN), private_key) mod (n/2) + 1`,
/// matching the Starknet Privacy SDK's expected `[1, n/2]` range.
///
/// # Arguments
/// * `private_key` - The Stark private key as a hex string.
///
/// # Returns
/// The viewing key as a `0x`-prefixed hex string.
#[wasm_bindgen(js_name = "deriveStrk20ViewingKey")]
pub fn derive_strk20_viewing_key(private_key: &str) -> Result<String, JsValue> {
    let pk = Felt::from_hex(private_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid private key hex: {e}")))?;
    let viewing_key = krusty_kms::strk20::derive_strk20_viewing_key(&pk);
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
            derive_strk20_viewing_key("0x1").unwrap(),
            "0x18c6e892dbe125696102d8c69a3adc9ca0c73d92bcb35fa166c2cb92914ba05",
        );
    }

    #[wasm_bindgen_test]
    fn derive_viewing_key_rejects_bad_hex() {
        assert!(derive_strk20_viewing_key("not-hex").is_err());
    }
}
