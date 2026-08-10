//! Mnemonic handling and Stark-curve HD key derivation (Tongo, Starknet,
//! and Argent-legacy schemes), plus coin type constants.

use crate::error::from_sdk_result;
use crate::types::{WasmKeypair, WasmPublicKey, WasmStarkXOnlyKeypair, WasmStarkXOnlyPublicKey};
use krusty_kms_common::SecretFelt;
use wasm_bindgen::prelude::*;

/// Generate a new random mnemonic phrase.
///
/// # Security / threat model
///
/// The mnemonic is returned as a plain JavaScript string and cannot be
/// reliably wiped from the JS heap. Treat it as high-value secret material:
/// never log it, never persist it unencrypted, and prefer keeping it only in
/// secure storage after generation.
#[wasm_bindgen(js_name = "generateMnemonic")]
pub fn generate_mnemonic(word_count: Option<u8>) -> Result<String, JsValue> {
    let count = word_count.unwrap_or(12) as usize;
    from_sdk_result(krusty_kms::generate_mnemonic(count)).map_err(JsValue::from)
}

/// Validate a mnemonic phrase.
#[wasm_bindgen(js_name = "validateMnemonic")]
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    krusty_kms::validate_mnemonic(mnemonic).is_ok()
}

/// Derive a keypair from mnemonic (for external use).
///
/// # Security / threat model
///
/// Returns the private key as a hex string in the JS heap. Prefer
/// [`derive_public_key`] when only the public key is needed. Never log the
/// returned [`WasmKeypair`]; its `Debug` form redacts the private key, but
/// JS property access still exposes it.
#[wasm_bindgen(js_name = "deriveKeypair")]
pub fn derive_keypair(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
) -> Result<WasmKeypair, JsValue> {
    let kp = from_sdk_result(krusty_kms::derive_keypair(
        mnemonic,
        address_index,
        account_index,
        passphrase.as_deref(),
    ))
    .map_err(JsValue::from)?;

    let affine = kp
        .public_key
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid public key point"))?;

    Ok(WasmKeypair {
        private_key: kp.private_key.expose_secret_hex(),
        public_key_x: format!("{:#x}", affine.x()),
        public_key_y: format!("{:#x}", affine.y()),
    })
}

/// Derive the public key only from a mnemonic (Tongo coin type).
///
/// Prefer this over [`derive_keypair`] when private key material is not needed.
#[wasm_bindgen(js_name = "derivePublicKey")]
pub fn derive_public_key(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
) -> Result<WasmPublicKey, JsValue> {
    let kp = from_sdk_result(krusty_kms::derive_keypair(
        mnemonic,
        address_index,
        account_index,
        passphrase.as_deref(),
    ))
    .map_err(JsValue::from)?;

    let affine = kp
        .public_key
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid public key point"))?;

    Ok(WasmPublicKey {
        public_key_x: format!("{:#x}", affine.x()),
        public_key_y: format!("{:#x}", affine.y()),
    })
}

/// Derive a Starknet account keypair from mnemonic (coin type 9004).
///
/// This is used for signing Starknet transactions and deriving the
/// OpenZeppelin account contract address.
///
/// # Security / threat model
///
/// Returns the private key as a hex string in the JS heap. Prefer
/// [`derive_starknet_public_key`] when only the public key is needed.
///
/// # Arguments
/// * `mnemonic` - 12 or 24 word BIP-39 mnemonic
/// * `address_index` - HD wallet address index (default: 0)
/// * `account_index` - HD wallet account index (default: 0)
/// * `passphrase` - Optional BIP-39 passphrase
///
/// # Returns
/// Keypair with private key and public key coordinates
#[wasm_bindgen(js_name = "deriveStarknetKeypair")]
pub fn derive_starknet_keypair(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
) -> Result<WasmKeypair, JsValue> {
    let kp = from_sdk_result(krusty_kms::derive_keypair_with_coin_type(
        mnemonic,
        address_index,
        account_index,
        krusty_kms::STARKNET_COIN_TYPE,
        passphrase.as_deref(),
    ))
    .map_err(JsValue::from)?;

    let affine = kp
        .public_key
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid public key point"))?;

    Ok(WasmKeypair {
        private_key: kp.private_key.expose_secret_hex(),
        public_key_x: format!("{:#x}", affine.x()),
        public_key_y: format!("{:#x}", affine.y()),
    })
}

/// Derive the Starknet public key only from a mnemonic (coin type 9004).
///
/// Prefer this over [`derive_starknet_keypair`] when private key material is
/// not needed (e.g. address derivation).
#[wasm_bindgen(js_name = "deriveStarknetPublicKey")]
pub fn derive_starknet_public_key(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
) -> Result<WasmPublicKey, JsValue> {
    let kp = from_sdk_result(krusty_kms::derive_keypair_with_coin_type(
        mnemonic,
        address_index,
        account_index,
        krusty_kms::STARKNET_COIN_TYPE,
        passphrase.as_deref(),
    ))
    .map_err(JsValue::from)?;

    let affine = kp
        .public_key
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid public key point"))?;

    Ok(WasmPublicKey {
        public_key_x: format!("{:#x}", affine.x()),
        public_key_y: format!("{:#x}", affine.y()),
    })
}

/// Get the Starknet coin type constant (9004).
#[wasm_bindgen(js_name = "getStarknetCoinType")]
pub fn get_starknet_coin_type() -> u32 {
    krusty_kms::STARKNET_COIN_TYPE
}

/// Get the Tongo coin type constant (5454).
#[wasm_bindgen(js_name = "getTongoCoinType")]
pub fn get_tongo_coin_type() -> u32 {
    krusty_kms::TONGO_COIN_TYPE
}

/// Get the Nostr coin type constant (1237).
#[wasm_bindgen(js_name = "getNostrCoinType")]
pub fn get_nostr_coin_type() -> u32 {
    krusty_kms::NOSTR_COIN_TYPE
}

/// Derive a Starknet keypair using old Argent's "double derivation" scheme.
///
/// Old Argent wallets use a two-step derivation:
/// 1. Derive ETH private key at `m/44'/60'/0'/0/0` (raw, no grindKey)
/// 2. Use ETH key as BIP-32 seed, derive `m/44'/9004'/0'/0/{index}`, then grindKey
///
/// This is needed to recover keys for accounts created with old Argent-X.
/// Braavos and new Argent use direct `m/44'/9004'/0'/0/{index}` derivation instead.
///
/// Returns an x-only Stark keypair ([`WasmStarkXOnlyKeypair`]) because
/// `stark_public_key` does not produce an affine Y coordinate.
///
/// # Security / threat model
///
/// Returns the private key as a hex string in the JS heap. Prefer
/// [`derive_argent_legacy_public_key`] when only the public key is needed.
///
/// # Arguments
/// * `mnemonic` - 12 or 24 word BIP-39 mnemonic
/// * `address_index` - HD wallet address index (default: 0)
/// * `account_index` - HD wallet account index (default: 0)
#[wasm_bindgen(js_name = "deriveArgentLegacyKeypair")]
pub fn derive_argent_legacy_keypair(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
) -> Result<WasmStarkXOnlyKeypair, JsValue> {
    let pk = SecretFelt::new(
        krusty_kms::derive_argent_legacy_private_key(mnemonic, address_index, account_index)
            .map_err(|e| JsValue::from_str(&format!("Argent legacy derivation failed: {e}")))?,
    );
    let pubk = krusty_kms::stark_public_key(pk.expose_secret())
        .map_err(|e| JsValue::from_str(&format!("Argent legacy key is invalid: {e}")))?;

    Ok(WasmStarkXOnlyKeypair {
        private_key: format!("{:#066x}", pk.expose_secret()),
        public_key_x: format!("{:#x}", pubk),
    })
}

/// Derive the Argent-legacy Stark public key only (x-coordinate).
///
/// Prefer this over [`derive_argent_legacy_keypair`] when private key material
/// is not needed. Returns [`WasmStarkXOnlyPublicKey`] because
/// `stark_public_key` is x-only (not a full affine point).
#[wasm_bindgen(js_name = "deriveArgentLegacyPublicKey")]
pub fn derive_argent_legacy_public_key(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
) -> Result<WasmStarkXOnlyPublicKey, JsValue> {
    let pk = SecretFelt::new(
        krusty_kms::derive_argent_legacy_private_key(mnemonic, address_index, account_index)
            .map_err(|e| JsValue::from_str(&format!("Argent legacy derivation failed: {e}")))?,
    );
    let pubk = krusty_kms::stark_public_key(pk.expose_secret())
        .map_err(|e| JsValue::from_str(&format!("Argent legacy key is invalid: {e}")))?;

    Ok(WasmStarkXOnlyPublicKey {
        public_key_x: format!("{:#x}", pubk),
    })
}
