//! WASM bindings for QSB-HORS-v1 vault secrets (Quantum Safe Bitcoin).
//!
//! These are the only exports that touch QSB secret material, and none of them
//! returns the derivation key `K` or a complete secret set. The caller keeps
//! the disclosure journal: it records the digest from `qsbRevealDigest` as
//! `exposed` before it calls `revealQsbPreimages`.
//!
//! Numeric arguments arrive as `JsValue` and must be exact, non-negative
//! integers. wasm-bindgen's `u8`/`u16`/`u32` conversions wrap out-of-range
//! numbers (`256` becomes `0`, `2^32 + 7` becomes `7`), which would silently
//! select a different namespace, vault, or secret.

#[cfg(test)]
mod tests;

use krusty_kms::{QsbRevealIndices, QsbVault};
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// The public commitments of one vault and their root.
#[derive(Debug, Clone)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmQsbCommitments {
    /// The 150 round-0 commitments `c[v][0][i]`, in index order (40 lowercase hex chars each).
    pub round0: Vec<String>,
    /// The 150 round-1 commitments `c[v][1][i]`, in index order (40 lowercase hex chars each).
    pub round1: Vec<String>,
    /// The commitment root `R[v]` (64 lowercase hex chars).
    pub root: String,
}

/// The transaction binding of a disclosure request.
#[derive(Debug, Clone)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmQsbRevealDigest {
    /// `B = SHA256(T)` (64 lowercase hex chars).
    pub binding: String,
    /// `D = SHA256("QSB-HORS-v1/reveal" || I || B)` (64 lowercase hex chars).
    pub digest: String,
}

fn js_error(message: impl core::fmt::Display) -> JsValue {
    js_sys::Error::new(&message.to_string()).into()
}

fn exact<T: DeserializeOwned>(value: JsValue, label: &str) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|_| js_error(format!("Invalid {label}: expected integers in range")))
}

fn vault(net: JsValue, vault_index: JsValue) -> Result<QsbVault, JsValue> {
    let net = exact(net, "QSB namespace")?;
    let vault_index = exact(vault_index, "QSB vault index")?;
    QsbVault::new(net, vault_index).map_err(js_error)
}

fn reveal_indices(round0: JsValue, round1: JsValue) -> Result<QsbRevealIndices, JsValue> {
    let round0: Vec<u16> = exact(round0, "QSB round 0 indices")?;
    let round1: Vec<u16> = exact(round1, "QSB round 1 indices")?;
    QsbRevealIndices::new(&round0, &round1).map_err(js_error)
}

/// Strict transaction hex: lowercase, no prefix, even length.
fn transaction_bytes(transaction_hex: &str) -> Result<Vec<u8>, JsValue> {
    if transaction_hex
        .bytes()
        .any(|byte| byte.is_ascii_uppercase())
    {
        return Err(js_error("Invalid QSB transaction hex: expected lowercase"));
    }
    hex::decode(transaction_hex)
        .map_err(|error| js_error(format!("Invalid QSB transaction hex: {error}")))
}

/// Derive the 2 × 150 commitments and the root of a QSB vault.
///
/// `net` is `0` (Bitcoin mainnet) or `1` (shared test namespace) and
/// `vault_index` is below `2^31`; both are validated before the mnemonic is
/// read. Deriving commitments does not allocate the vault.
///
/// # Arguments
/// * `mnemonic` - BIP-39 mnemonic of the dedicated QSB phrase
/// * `net` - Derivation namespace
/// * `vault_index` - Vault index `v`
/// * `passphrase` - Optional BIP-39 passphrase
#[wasm_bindgen(js_name = "deriveQsbCommitments")]
pub fn derive_qsb_commitments(
    mnemonic: &str,
    #[wasm_bindgen(unchecked_param_type = "number")] net: JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] vault_index: JsValue,
    passphrase: Option<String>,
) -> Result<WasmQsbCommitments, JsValue> {
    let vault = vault(net, vault_index)?;
    let commitments = krusty_kms::derive_qsb_commitments(mnemonic, vault, passphrase.as_deref())
        .map_err(js_error)?;
    Ok(WasmQsbCommitments {
        round0: commitments.round0.iter().map(hex::encode).collect(),
        round1: commitments.round1.iter().map(hex::encode).collect(),
        root: hex::encode(commitments.root),
    })
}

/// Compute `B` and `D` for a disclosure request.
///
/// `transaction_hex` is the BIP's `T` as lowercase hex: the full legacy
/// serialization with every scriptSig empty and no witness. Krusty parses it
/// and refuses anything else; it never accepts a caller-supplied hash.
/// `round0` must hold 8 and `round1` 7 distinct indices below 150, in the
/// order the spend reveals them.
#[wasm_bindgen(js_name = "qsbRevealDigest")]
pub fn qsb_reveal_digest(
    transaction_hex: &str,
    #[wasm_bindgen(unchecked_param_type = "number[]")] round0: JsValue,
    #[wasm_bindgen(unchecked_param_type = "number[]")] round1: JsValue,
) -> Result<WasmQsbRevealDigest, JsValue> {
    let indices = reveal_indices(round0, round1)?;
    let transaction = transaction_bytes(transaction_hex)?;
    let digest = krusty_kms::qsb_reveal_digest(&transaction, &indices).map_err(js_error)?;
    Ok(WasmQsbRevealDigest {
        binding: hex::encode(digest.binding),
        digest: hex::encode(digest.digest),
    })
}

/// Reveal the 15 preimages a disclosure request names.
///
/// Returns 15 lowercase hex strings: round 0's then round 1's, in the given
/// order. Every parameter is validated before the mnemonic is read.
///
/// # Security / threat model
///
/// Call only after durably recording this request as `exposed`. The returned
/// preimages are spending secrets. Krusty wipes its own copies, including
/// their hex encoding, before returning; the JS strings cannot be wiped.
#[wasm_bindgen(js_name = "revealQsbPreimages", unchecked_return_type = "string[]")]
pub fn reveal_qsb_preimages(
    mnemonic: &str,
    #[wasm_bindgen(unchecked_param_type = "number")] net: JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] vault_index: JsValue,
    #[wasm_bindgen(unchecked_param_type = "number[]")] round0: JsValue,
    #[wasm_bindgen(unchecked_param_type = "number[]")] round1: JsValue,
    passphrase: Option<String>,
) -> Result<js_sys::Array, JsValue> {
    let vault = vault(net, vault_index)?;
    let indices = reveal_indices(round0, round1)?;
    let preimages =
        krusty_kms::reveal_qsb_preimages(mnemonic, vault, &indices, passphrase.as_deref())
            .map_err(js_error)?;
    let revealed = js_sys::Array::new();
    let mut encoded = Zeroizing::new([0u8; 40]);
    for preimage in preimages.as_array() {
        hex::encode_to_slice(preimage, encoded.as_mut_slice()).map_err(js_error)?;
        let text = core::str::from_utf8(encoded.as_slice()).map_err(js_error)?;
        revealed.push(&JsValue::from_str(text));
    }
    Ok(revealed)
}
