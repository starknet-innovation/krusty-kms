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

/// Compute the message a STRK20 viewing key is derived by signing.
///
/// The first of the two stages [`derive_strk20_viewing_key`] composes. Callers
/// whose signing key is held in hardware sign this hash on the device, then fold
/// the result with [`fold_strk20_viewing_key`] to reach the same viewing key a
/// host-held key would produce. Scope canonicalization happens here, so the
/// message never depends on how the caller spelled the chain id or pool address.
///
/// # Arguments
/// * `chain_id` - The active Starknet chain id as a canonical hex string.
/// * `pool_address` - The active privacy pool address as a canonical hex string.
///
/// # Returns
/// The message hash as a `0x`-prefixed hex string.
#[wasm_bindgen(js_name = "strk20ViewingKeyMessageHash")]
pub fn strk20_viewing_key_message_hash(
    chain_id: &str,
    pool_address: &str,
) -> Result<String, JsValue> {
    let message_hash = krusty_kms::strk20::strk20_viewing_key_message_hash(chain_id, pool_address)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(format!("{:#x}", message_hash))
}

/// Fold an ECDSA signature over the viewing-key message into the viewing key.
///
/// The second of the two stages. Independent of how `(r, s)` was produced, so a
/// device signature folds exactly as a host signature does. Always returns a key
/// in `[1, n/2]`, the range the pool accepts.
///
/// The argument order is load-bearing: swapping `r` and `s` yields a different
/// key that still looks valid.
///
/// # Arguments
/// * `r` - The signature's `r` component as a hex string.
/// * `s` - The signature's `s` component as a hex string.
///
/// # Returns
/// The viewing key as a `0x`-prefixed hex string.
#[wasm_bindgen(js_name = "foldStrk20ViewingKey")]
pub fn fold_strk20_viewing_key(r: &str, s: &str) -> Result<String, JsValue> {
    let r = Felt::from_hex(r).map_err(|e| JsValue::from_str(&format!("Invalid r hex: {e}")))?;
    let s = Felt::from_hex(s).map_err(|e| JsValue::from_str(&format!("Invalid s hex: {e}")))?;
    Ok(format!(
        "{:#x}",
        krusty_kms::strk20::fold_strk20_viewing_key(&r, &s)
    ))
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

    /// The JS-facing stages must compose to the same key the one-shot binding
    /// returns. This is the guarantee a hardware-signer caller depends on: it
    /// only ever calls the two stages, and must land on the same key.
    #[wasm_bindgen_test]
    fn viewing_key_stages_compose_to_the_one_shot_key() {
        let chain_id = "0x534e5f5345504f4c4941";
        let pool_address = "0x123";

        let message_hash = strk20_viewing_key_message_hash(chain_id, pool_address).unwrap();
        let signature = krusty_kms::sign_stark_hash(
            &Felt::from_hex("0x1").unwrap(),
            &Felt::from_hex(&message_hash).unwrap(),
        )
        .unwrap();
        let folded = fold_strk20_viewing_key(
            &format!("{:#x}", signature.r),
            &format!("{:#x}", signature.s),
        )
        .unwrap();

        assert_eq!(
            folded,
            derive_strk20_viewing_key("0x1", chain_id, pool_address).unwrap(),
        );
    }

    #[wasm_bindgen_test]
    fn viewing_key_stages_reject_bad_input() {
        assert!(strk20_viewing_key_message_hash("0x01", "0x2").is_err());
        assert!(strk20_viewing_key_message_hash("0x1", "0x0").is_err());
        assert!(fold_strk20_viewing_key("not-hex", "0x2").is_err());
        assert!(fold_strk20_viewing_key("0x1", "not-hex").is_err());
    }

    #[wasm_bindgen_test]
    fn derive_viewing_key_rejects_bad_hex() {
        assert!(derive_strk20_viewing_key("not-hex", "0x1", "0x2").is_err());
        assert!(derive_strk20_viewing_key("0x1", "0x01", "0x2").is_err());
    }
}
