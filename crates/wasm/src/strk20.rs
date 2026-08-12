//! WASM bindings for STRK20 privacy-pool key derivation.

use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

fn parse_felt_without_reduction(value: &str, label: &str) -> Result<Felt, JsValue> {
    let felt = Felt::from_hex(value)
        .map_err(|error| JsValue::from_str(&format!("Invalid {label} hex: {error}")))?;
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let round_trip = !digits.is_empty()
        && digits.len() <= 64
        && digits
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        && format!("{:0>64}", digits.to_ascii_lowercase()) == format!("{felt:064x}");
    if !round_trip {
        return Err(JsValue::from_str(&format!(
            "Invalid {label}: value is not a field element"
        )));
    }
    Ok(felt)
}

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

/// Derive a chain- and pool-scoped STRK20 viewing key.
#[wasm_bindgen(js_name = "deriveScopedStrk20ViewingKey")]
pub fn derive_scoped_strk20_viewing_key(
    private_key: &str,
    chain_id: &str,
    pool_address: &str,
) -> Result<String, JsValue> {
    let private_key = parse_felt_without_reduction(private_key, "private key")?;
    let viewing_key =
        krusty_kms::strk20::derive_scoped_strk20_viewing_key(&private_key, chain_id, pool_address)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
    Ok(format!("{viewing_key:#x}"))
}

/// Return the hash a hardware signer must sign for a scoped viewing key.
#[wasm_bindgen(js_name = "strk20ViewingKeyMessageHash")]
pub fn strk20_viewing_key_message_hash(
    chain_id: &str,
    pool_address: &str,
) -> Result<String, JsValue> {
    let message_hash = krusty_kms::strk20::strk20_viewing_key_message_hash(chain_id, pool_address)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    Ok(format!("{message_hash:#x}"))
}

/// Verify and fold a hardware-produced Stark signature into a scoped viewing key.
///
/// `public_key` must be the expected signer's Stark public-key x-coordinate.
#[wasm_bindgen(js_name = "foldStrk20ViewingKey")]
pub fn fold_strk20_viewing_key(
    public_key: &str,
    message_hash: &str,
    r: &str,
    s: &str,
) -> Result<String, JsValue> {
    let public_key = parse_felt_without_reduction(public_key, "public key")?;
    let message_hash = parse_felt_without_reduction(message_hash, "message hash")?;
    let r = parse_felt_without_reduction(r, "signature r")?;
    let s = parse_felt_without_reduction(s, "signature s")?;
    let viewing_key =
        krusty_kms::strk20::fold_strk20_viewing_key(&public_key, &message_hash, &r, &s)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
    Ok(format!("{viewing_key:#x}"))
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

    #[wasm_bindgen_test]
    fn scoped_stages_compose() {
        let chain_id = "0x534e5f5345504f4c4941";
        let pool_address = "0x123";
        let message_hash = strk20_viewing_key_message_hash(chain_id, pool_address).unwrap();
        let signature =
            krusty_kms::sign_stark_hash(&Felt::ONE, &Felt::from_hex(&message_hash).unwrap())
                .unwrap();
        let folded = fold_strk20_viewing_key(
            &format!("{:#x}", signature.public_key),
            &message_hash,
            &format!("{:#x}", signature.r),
            &format!("{:#x}", signature.s),
        )
        .unwrap();

        assert_eq!(
            folded,
            derive_scoped_strk20_viewing_key("0x1", chain_id, pool_address).unwrap(),
        );
    }

    #[wasm_bindgen_test]
    fn staged_inputs_fail_closed() {
        const FIELD_PRIME: &str =
            "0x0800000000000011000000000000000000000000000000000000000000000001";
        assert!(strk20_viewing_key_message_hash("0x01", "0x2").is_err());
        assert!(derive_scoped_strk20_viewing_key(FIELD_PRIME, "0x1", "0x2").is_err());
        assert!(fold_strk20_viewing_key("0x1", "0x2", "0x0", "0x1").is_err());
        assert!(fold_strk20_viewing_key(FIELD_PRIME, "0x2", "0x1", "0x1").is_err());
    }
}
