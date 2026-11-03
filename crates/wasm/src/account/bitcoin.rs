//! WASM bindings for Bitcoin mainnet P2WPKH keys: BIP-84 derivation, PSBT
//! input signing, and BIP-322 simple message signatures.
//!
//! Private keys cross this boundary as 64 hex characters without a `0x`
//! prefix, the secp256k1 convention also used by the Nostr bindings. Rejected
//! inputs fail with a JS error and no output.

use crate::error::from_sdk_result;
use serde::{Deserialize, Serialize};
use std::fmt;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// BIP-84 mainnet P2WPKH keypair.
///
/// # Security / threat model
///
/// `private_key` is a plain hex string in the JS heap and cannot be reliably
/// wiped. The copy this object owns in WASM memory is zeroized when the
/// object is freed, as for [`crate::WasmKeypair`]. `Debug` redacts the
/// private key; default `Serialize` omits it.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmBitcoinP2wpkhKeypair {
    /// Private key as 64 hex chars (no 0x prefix). Treat as secret.
    #[serde(skip_serializing)]
    pub private_key: String,
    /// Compressed SEC1 public key as 66 hex chars (no 0x prefix).
    #[zeroize(skip)]
    pub public_key: String,
    /// Lowercase `bc1q…` P2WPKH address.
    #[zeroize(skip)]
    pub address: String,
    /// Derivation path, e.g. `m/84'/0'/0'/0/0`.
    #[zeroize(skip)]
    pub path: String,
}

impl fmt::Debug for WasmBitcoinP2wpkhKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmBitcoinP2wpkhKeypair")
            .field("private_key", &"***")
            .field("public_key", &self.public_key)
            .field("address", &self.address)
            .field("path", &self.path)
            .finish()
    }
}

/// Derive the BIP-84 mainnet P2WPKH keypair at
/// `m/84'/0'/{account_index}'/{change}/{address_index}`.
///
/// # Security / threat model
///
/// Returns the private key as a hex string in the JS heap.
///
/// # Arguments
/// * `mnemonic` - BIP-39 mnemonic
/// * `account_index` - hardened account index (< 2^31)
/// * `change` - 0 for receiving, 1 for change
/// * `address_index` - address index (< 2^31)
/// * `passphrase` - Optional BIP-39 passphrase
#[wasm_bindgen(js_name = "deriveBitcoinP2wpkhKeypair")]
pub fn derive_bitcoin_p2wpkh_keypair(
    mnemonic: &str,
    account_index: u32,
    change: u32,
    address_index: u32,
    passphrase: Option<String>,
) -> Result<WasmBitcoinP2wpkhKeypair, JsValue> {
    let keypair = from_sdk_result(krusty_kms::derive_bitcoin_p2wpkh_keypair(
        mnemonic,
        account_index,
        change,
        address_index,
        passphrase.as_deref(),
    ))
    .map_err(JsValue::from)?;

    Ok(WasmBitcoinP2wpkhKeypair {
        private_key: hex::encode(keypair.private_key),
        public_key: hex::encode(keypair.public_key),
        address: keypair.address.clone(),
        path: keypair.path.clone(),
    })
}

/// Add this key's SIGHASH_ALL partial signature to the listed inputs of a
/// base64 PSBT (version 0) and return the PSBT as base64.
///
/// Each listed input must be this key's P2WPKH coin, proven by a
/// `witness_utxo` that matches the spent output of its full
/// `non_witness_utxo`, and must not request a sighash type other than
/// SIGHASH_ALL. Every other input and field is returned byte-identical. The
/// PSBT is not finalized or broadcast.
///
/// # Arguments
/// * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
/// * `psbt_base64` - the PSBT, standard base64 with padding
/// * `input_indices` - the inputs to sign; non-empty, distinct, in range
#[wasm_bindgen(js_name = "signBitcoinPsbtInputs")]
pub fn sign_bitcoin_psbt_inputs(
    private_key: &str,
    psbt_base64: &str,
    input_indices: Vec<u32>,
) -> Result<String, JsValue> {
    let key = parse_private_key(private_key)?;
    krusty_kms::sign_bitcoin_psbt_inputs(&key, psbt_base64, &input_indices)
        .map_err(|e| JsValue::from_str(&format!("Bitcoin PSBT signing failed: {e}")))
}

/// Sign a UTF-8 message with a BIP-322 "simple" signature for this key's
/// P2WPKH address and return the base64 witness (no `smp` prefix).
///
/// # Arguments
/// * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
/// * `address` - must be this key's mainnet P2WPKH address
/// * `message` - the message; signed as its UTF-8 bytes
#[wasm_bindgen(js_name = "signBip322Simple")]
pub fn sign_bip322_simple(
    private_key: &str,
    address: &str,
    message: &str,
) -> Result<String, JsValue> {
    let key = parse_private_key(private_key)?;
    krusty_kms::sign_bip322_simple(&key, address, message.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("BIP-322 signing failed: {e}")))
}

/// Decode exactly 64 hex chars into a zeroizing 32-byte key. The input is
/// never echoed in errors.
fn parse_private_key(private_key: &str) -> Result<Zeroizing<[u8; 32]>, JsValue> {
    let mut key = Zeroizing::new([0u8; 32]);
    if private_key.len() != 64 || hex::decode_to_slice(private_key, key.as_mut()).is_err() {
        return Err(JsValue::from_str(
            "Bitcoin private key must be exactly 64 hex chars (32 bytes, no 0x prefix)",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests;
