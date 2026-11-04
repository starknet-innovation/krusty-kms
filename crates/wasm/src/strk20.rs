//! WASM bindings for STRK20 privacy-pool key derivation.
//!
//! Private keys and the signature folded into a viewing key are taken as
//! owned strings and wiped when the call returns, and so are the parsed felts.
//! The returned viewing keys are secret and stay in the JS heap (see
//! [`crate`]).

use crate::secret_input::parse_secret_felt;
use krusty_kms_common::SecretFelt;
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Parse a felt that must not be reduced. It comes back as a [`SecretFelt`]
/// because most callers parse secrets; a public input is wiped harmlessly.
fn parse_felt_without_reduction(value: &str, label: &str) -> Result<SecretFelt, JsValue> {
    let felt = parse_secret_felt(value, &format!("Invalid {label} hex"))?;
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if !is_unreduced_hex(digits, felt.expose_secret()) {
        return Err(JsValue::from_str(&format!(
            "Invalid {label}: value is not a field element"
        )));
    }
    Ok(felt)
}

/// Whether `digits` (no prefix, either case) spell exactly `felt`, so parsing
/// did not reduce them. Compared in wiped stack buffers: formatting either side
/// into a `String` would leave a copy of a private key behind.
fn is_unreduced_hex(digits: &str, felt: &Felt) -> bool {
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let mut canonical = Zeroizing::new([0u8; 64]);
    let bytes = Zeroizing::new(felt.to_bytes_be());
    if hex::encode_to_slice(bytes.as_slice(), canonical.as_mut_slice()).is_err() {
        return false;
    }
    let (padding, tail) = canonical.split_at(64 - digits.len());
    padding.iter().all(|&byte| byte == b'0') && tail.eq_ignore_ascii_case(digits.as_bytes())
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
pub fn derive_strk20_viewing_key(private_key: String) -> Result<String, JsValue> {
    let pk = parse_secret_felt(&Zeroizing::new(private_key), "Invalid private key hex")?;
    let viewing_key = krusty_kms::strk20::derive_strk20_viewing_key(pk.expose_secret());
    Ok(format!("{:#x}", viewing_key))
}

/// Derive a chain- and pool-scoped STRK20 viewing key.
#[wasm_bindgen(js_name = "deriveScopedStrk20ViewingKey")]
pub fn derive_scoped_strk20_viewing_key(
    private_key: String,
    chain_id: &str,
    pool_address: &str,
) -> Result<String, JsValue> {
    let private_key = parse_felt_without_reduction(&Zeroizing::new(private_key), "private key")?;
    let viewing_key = krusty_kms::strk20::derive_scoped_strk20_viewing_key(
        private_key.expose_secret(),
        chain_id,
        pool_address,
    )
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
    r: String,
    s: String,
) -> Result<String, JsValue> {
    // The viewing key is a function of `(r, s)` alone: both are secret.
    let (r, s) = (Zeroizing::new(r), Zeroizing::new(s));
    let public_key = parse_felt_without_reduction(public_key, "public key")?;
    let message_hash = parse_felt_without_reduction(message_hash, "message hash")?;
    let r = parse_felt_without_reduction(&r, "signature r")?;
    let s = parse_felt_without_reduction(&s, "signature s")?;
    let viewing_key = krusty_kms::strk20::fold_strk20_viewing_key(
        public_key.expose_secret(),
        message_hash.expose_secret(),
        r.expose_secret(),
        s.expose_secret(),
    )
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
            derive_strk20_viewing_key("0x1".into()).unwrap(),
            "0x18c6e892dbe125696102d8c69a3adc9ca0c73d92bcb35fa166c2cb92914ba05",
        );
    }

    #[wasm_bindgen_test]
    fn derive_viewing_key_rejects_bad_hex() {
        assert!(derive_strk20_viewing_key("not-hex".into()).is_err());
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
            format!("{:#x}", signature.r),
            format!("{:#x}", signature.s),
        )
        .unwrap();

        assert_eq!(
            folded,
            derive_scoped_strk20_viewing_key("0x1".into(), chain_id, pool_address).unwrap(),
        );
    }

    #[wasm_bindgen_test]
    fn staged_inputs_fail_closed() {
        const FIELD_PRIME: &str =
            "0x0800000000000011000000000000000000000000000000000000000000000001";
        assert!(strk20_viewing_key_message_hash("0x01", "0x2").is_err());
        assert!(derive_scoped_strk20_viewing_key(FIELD_PRIME.into(), "0x1", "0x2").is_err());
        assert!(fold_strk20_viewing_key("0x1", "0x2", "0x0".into(), "0x1".into()).is_err());
        assert!(fold_strk20_viewing_key(FIELD_PRIME, "0x2", "0x1".into(), "0x1".into()).is_err());
    }
}
