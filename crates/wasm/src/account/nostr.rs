//! Nostr (secp256k1 / BIP-340) key derivation.

use crate::error::from_sdk_result;
use crate::numeric_input;
use crate::types::{WasmNostrKeypair, WasmNostrPublicKey};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Derive a Nostr keypair from mnemonic (coin type 1237).
///
/// Uses secp256k1 curve (not Stark curve). The public key is x-only
/// (32 bytes) as per BIP-340/Nostr convention.
///
/// Derivation path: m/44'/1237'/{account_index}'/0/{address_index}
///
/// # Security / threat model
///
/// Returns the private key as a hex string in the JS heap. Prefer
/// [`derive_nostr_public_key`] when only the public key is needed.
///
/// # Arguments
/// * `mnemonic` - 12 or 24 word BIP-39 mnemonic
/// * `address_index` - HD wallet address index (default: 0)
/// * `account_index` - HD wallet account index (default: 0)
/// * `passphrase` - Optional BIP-39 passphrase
///
/// # Returns
/// Nostr keypair with private key and x-only public key (both 64 hex chars)
#[wasm_bindgen(js_name = "deriveNostrKeypair")]
pub fn derive_nostr_keypair(
    mnemonic: String,
    #[wasm_bindgen(unchecked_param_type = "number")] address_index: JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] account_index: JsValue,
    passphrase: Option<String>,
) -> Result<WasmNostrKeypair, JsValue> {
    let mnemonic = Zeroizing::new(mnemonic);
    let passphrase = passphrase.map(Zeroizing::new);
    let (address_index, account_index) =
        numeric_input::derivation_indices(address_index, account_index)?;
    let kp = from_sdk_result(krusty_kms::derive_nostr_keypair(
        &mnemonic,
        address_index,
        account_index,
        passphrase.as_deref().map(String::as_str),
    ))
    .map_err(JsValue::from)?;

    // Convert to hex strings (no 0x prefix for Nostr compatibility)
    let private_key = hex::encode(kp.private_key);
    let public_key = hex::encode(kp.public_key);

    Ok(WasmNostrKeypair {
        private_key,
        public_key,
    })
}

/// Derive the Nostr x-only public key only from a mnemonic (coin type 1237).
///
/// Prefer this over [`derive_nostr_keypair`] when private key material is not needed.
#[wasm_bindgen(js_name = "deriveNostrPublicKey")]
pub fn derive_nostr_public_key(
    mnemonic: String,
    #[wasm_bindgen(unchecked_param_type = "number")] address_index: JsValue,
    #[wasm_bindgen(unchecked_param_type = "number")] account_index: JsValue,
    passphrase: Option<String>,
) -> Result<WasmNostrPublicKey, JsValue> {
    let mnemonic = Zeroizing::new(mnemonic);
    let passphrase = passphrase.map(Zeroizing::new);
    let (address_index, account_index) =
        numeric_input::derivation_indices(address_index, account_index)?;
    let kp = from_sdk_result(krusty_kms::derive_nostr_keypair(
        &mnemonic,
        address_index,
        account_index,
        passphrase.as_deref().map(String::as_str),
    ))
    .map_err(JsValue::from)?;

    Ok(WasmNostrPublicKey {
        public_key: hex::encode(kp.public_key),
    })
}
