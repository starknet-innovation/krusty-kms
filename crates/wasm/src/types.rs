//! WASM-compatible type definitions.
//!
//! Provides JavaScript-friendly types with serde serialization for
//! seamless interop between Rust WASM and TypeScript.

use crate::error::{WasmError, WasmResult};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use std::fmt;
use wasm_bindgen::prelude::*;

fn padded_public_key_hex(public_key_x: &str, public_key_y: &str) -> Result<String, JsValue> {
    let x = Felt::from_hex(public_key_x)
        .map_err(|_| JsValue::from_str("invalid public_key_x: expected felt hex"))?;
    let y = Felt::from_hex(public_key_y)
        .map_err(|_| JsValue::from_str("invalid public_key_y: expected felt hex"))?;
    Ok(krusty_kms_common::utils::serialize_public_key_hex(&x, &y))
}

fn padded_felt_hex(value: &str) -> Result<String, JsValue> {
    let felt = Felt::from_hex(value)
        .map_err(|_| JsValue::from_str("invalid public key felt: expected felt hex"))?;
    Ok(format!("{:#066x}", felt))
}

fn require_felt_hex(value: &str, field: &str) -> Result<(), JsValue> {
    Felt::from_hex(value)
        .map(|_| ())
        .map_err(|_| JsValue::from_str(&format!("invalid {field}: expected felt hex")))
}

/// Account state returned from on-chain queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmAccountState {
    /// Available balance (can be spent immediately)
    pub balance: String,
    /// Pending balance (requires rollover to become available)
    pub pending_balance: String,
    /// Current nonce for replay protection
    pub nonce: u64,
}

#[wasm_bindgen]
impl WasmAccountState {
    /// Create a new account state.
    #[wasm_bindgen(constructor)]
    pub fn new(
        balance: String,
        pending_balance: String,
        transaction_nonce: u64,
    ) -> Result<WasmAccountState, JsValue> {
        let state = Self {
            balance,
            pending_balance,
            nonce: transaction_nonce,
        };
        state.validate().map_err(JsValue::from)?;
        Ok(state)
    }

    /// Get total balance (available + pending).
    #[wasm_bindgen(js_name = "totalBalance")]
    pub fn total_balance(&self) -> Result<String, JsValue> {
        self.checked_total_balance()
            .map(|total| total.to_string())
            .map_err(JsValue::from)
    }
}

impl WasmAccountState {
    pub(crate) fn validate(&self) -> WasmResult<()> {
        let _ = parse_balance_field("balance", &self.balance)?;
        let _ = parse_balance_field("pending_balance", &self.pending_balance)?;
        Ok(())
    }

    pub(crate) fn checked_total_balance(&self) -> WasmResult<u128> {
        let balance = parse_balance_field("balance", &self.balance)?;
        let pending = parse_balance_field("pending_balance", &self.pending_balance)?;
        balance.checked_add(pending).ok_or_else(|| {
            WasmError::InvalidAmount("account state total balance overflow".to_string())
        })
    }
}

impl From<krusty_kms_common::AccountState> for WasmAccountState {
    fn from(state: krusty_kms_common::AccountState) -> Self {
        Self {
            balance: state.balance.to_string(),
            pending_balance: state.pending_balance.to_string(),
            nonce: state.nonce,
        }
    }
}

impl TryFrom<WasmAccountState> for krusty_kms_common::AccountState {
    type Error = WasmError;

    fn try_from(state: WasmAccountState) -> Result<Self, Self::Error> {
        Ok(Self {
            balance: parse_balance_field("balance", &state.balance)?,
            pending_balance: parse_balance_field("pending_balance", &state.pending_balance)?,
            nonce: state.nonce,
        })
    }
}

fn parse_balance_field(field: &str, value: &str) -> WasmResult<u128> {
    value.parse().map_err(|_| {
        WasmError::SerializationError(format!("{field} must be a valid unsigned decimal string"))
    })
}

/// Point on the Stark curve (serialized as hex strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmPoint {
    pub x: String,
    pub y: String,
}

#[wasm_bindgen]
impl WasmPoint {
    #[wasm_bindgen(constructor)]
    pub fn new(x: String, y: String) -> Result<WasmPoint, JsValue> {
        let point = Self { x, y };
        point.validate().map_err(JsValue::from)?;
        Ok(point)
    }
}

impl WasmPoint {
    pub(crate) fn validate(&self) -> WasmResult<()> {
        let _ = parse_point_coordinate("x", &self.x)?;
        let _ = parse_point_coordinate("y", &self.y)?;
        Ok(())
    }
}

impl From<krusty_kms_common::SerializablePoint> for WasmPoint {
    fn from(p: krusty_kms_common::SerializablePoint) -> Self {
        Self {
            x: format!("{:#x}", p.x),
            y: format!("{:#x}", p.y),
        }
    }
}

impl TryFrom<WasmPoint> for krusty_kms_common::SerializablePoint {
    type Error = WasmError;

    fn try_from(point: WasmPoint) -> Result<Self, Self::Error> {
        Ok(Self {
            x: parse_point_coordinate("x", &point.x)?,
            y: parse_point_coordinate("y", &point.y)?,
        })
    }
}

fn parse_point_coordinate(label: &str, value: &str) -> WasmResult<Felt> {
    krusty_kms_common::utils::parse_hex_to_felt(value).map_err(|error| {
        WasmError::SerializationError(format!(
            "point {label} must be a valid felt hex string: {error}"
        ))
    })
}

/// Decrypted point result that can explicitly represent the identity point.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmDecryptedPoint {
    pub is_identity: bool,
    pub x: Option<String>,
    pub y: Option<String>,
}

#[wasm_bindgen]
impl WasmDecryptedPoint {
    #[wasm_bindgen(constructor)]
    pub fn new(is_identity: bool, x: Option<String>, y: Option<String>) -> Self {
        Self { is_identity, x, y }
    }
}

/// ElGamal ciphertext (L, R points).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmCiphertext {
    pub l_x: String,
    pub l_y: String,
    pub r_x: String,
    pub r_y: String,
}

#[wasm_bindgen]
impl WasmCiphertext {
    #[wasm_bindgen(constructor)]
    pub fn new(l_x: String, l_y: String, r_x: String, r_y: String) -> Self {
        Self { l_x, l_y, r_x, r_y }
    }
}

/// Keypair for Tongo / Starknet operations.
///
/// # Security / threat model
///
/// This type intentionally exposes `private_key` as a plain hex string for
/// JS interop (signing, export, wallet recovery). That string lives in the
/// JS heap and **cannot** be reliably wiped. Prefer companion public-only
/// APIs (`derivePublicKey`, etc.) when private material is not required.
/// Never `console.log` this value; `Debug` redacts the private key.
#[derive(Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmKeypair {
    /// Private key as hex string (0x-prefixed). Treat as secret.
    ///
    /// Omitted from default `Serialize` (use the wasm-bindgen getter for the
    /// intentional secret-returning API).
    #[serde(skip_serializing)]
    pub private_key: String,
    /// Public key X coordinate as hex string
    pub public_key_x: String,
    /// Public key Y coordinate as hex string
    pub public_key_y: String,
}

impl fmt::Debug for WasmKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmKeypair")
            .field("private_key", &"***")
            .field("public_key_x", &self.public_key_x)
            .field("public_key_y", &self.public_key_y)
            .finish()
    }
}

#[wasm_bindgen]
impl WasmKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new(
        private_key: String,
        public_key_x: String,
        public_key_y: String,
    ) -> Result<WasmKeypair, JsValue> {
        require_felt_hex(&public_key_x, "public_key_x")?;
        require_felt_hex(&public_key_y, "public_key_y")?;
        Ok(Self {
            private_key,
            public_key_x,
            public_key_y,
        })
    }

    /// Get the full public key as fixed-width `0x` + 128 hex digits (x||y).
    ///
    /// Compatible with `deserializePublicKey`.
    #[wasm_bindgen(js_name = "publicKeyHex")]
    pub fn public_key_hex(&self) -> Result<String, JsValue> {
        padded_public_key_hex(&self.public_key_x, &self.public_key_y)
    }
}

/// Public-only Stark / Tongo key material (no private key).
///
/// Prefer this over [`WasmKeypair`] when only the public key is needed
/// (address derivation, display, API lookups). Both affine coordinates are
/// populated; for x-only Stark keys use [`WasmStarkXOnlyPublicKey`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmPublicKey {
    /// Public key X coordinate as hex string
    pub public_key_x: String,
    /// Public key Y coordinate as hex string
    pub public_key_y: String,
}

/// Stark x-only keypair (private key + x-coordinate public key).
///
/// Used by Argent-legacy derivation where `stark_public_key` does not produce Y.
///
/// # Security / threat model
///
/// `private_key` is a plain hex string in the JS heap and cannot be reliably
/// wiped. Prefer [`WasmStarkXOnlyPublicKey`] when private material is not
/// required. `Debug` redacts the private key; default `Serialize` omits it.
#[derive(Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmStarkXOnlyKeypair {
    /// Private key as hex string (0x-prefixed). Treat as secret.
    #[serde(skip_serializing)]
    pub private_key: String,
    /// Public key X coordinate as hex string
    pub public_key_x: String,
}

impl fmt::Debug for WasmStarkXOnlyKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmStarkXOnlyKeypair")
            .field("private_key", &"***")
            .field("public_key_x", &self.public_key_x)
            .finish()
    }
}

#[wasm_bindgen]
impl WasmStarkXOnlyKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new(
        private_key: String,
        public_key_x: String,
    ) -> Result<WasmStarkXOnlyKeypair, JsValue> {
        require_felt_hex(&public_key_x, "public_key_x")?;
        Ok(Self {
            private_key,
            public_key_x,
        })
    }

    /// Return the x-only public key as fixed-width `0x` + 64 hex digits.
    #[wasm_bindgen(js_name = "publicKeyHex")]
    pub fn public_key_hex(&self) -> Result<String, JsValue> {
        padded_felt_hex(&self.public_key_x)
    }
}

/// Stark public key as an x-only felt (no Y coordinate).
///
/// Matches `stark_public_key` / account address derivation inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmStarkXOnlyPublicKey {
    /// Public key X coordinate as hex string
    pub public_key_x: String,
}

#[wasm_bindgen]
impl WasmStarkXOnlyPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key_x: String) -> Result<WasmStarkXOnlyPublicKey, JsValue> {
        require_felt_hex(&public_key_x, "public_key_x")?;
        Ok(Self { public_key_x })
    }

    /// Return the x-only public key as fixed-width `0x` + 64 hex digits.
    #[wasm_bindgen(js_name = "publicKeyHex")]
    pub fn public_key_hex(&self) -> Result<String, JsValue> {
        padded_felt_hex(&self.public_key_x)
    }
}

#[wasm_bindgen]
impl WasmPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key_x: String, public_key_y: String) -> Result<WasmPublicKey, JsValue> {
        require_felt_hex(&public_key_x, "public_key_x")?;
        require_felt_hex(&public_key_y, "public_key_y")?;
        Ok(Self {
            public_key_x,
            public_key_y,
        })
    }

    /// Get the full public key as fixed-width `0x` + 128 hex digits (x||y).
    ///
    /// Compatible with `deserializePublicKey`.
    #[wasm_bindgen(js_name = "publicKeyHex")]
    pub fn public_key_hex(&self) -> Result<String, JsValue> {
        padded_public_key_hex(&self.public_key_x, &self.public_key_y)
    }
}

/// Transaction type enum for Tongo operations.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmTxType {
    Fund = 0,
    Transfer = 1,
    Rollover = 2,
    Withdraw = 3,
    Ragequit = 4,
}

/// Nostr keypair (secp256k1, x-only public key).
///
/// Used for NIP-04/NIP-44 encrypted messaging.
/// Public key is x-only (32 bytes, BIP-340 format).
///
/// # Security / threat model
///
/// `private_key` is a plain hex string in the JS heap and cannot be reliably
/// wiped. Prefer [`WasmNostrPublicKey`] / `deriveNostrPublicKey` when private
/// material is not required. `Debug` redacts the private key.
#[derive(Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmNostrKeypair {
    /// Private key as hex string (64 hex chars, no 0x prefix). Treat as secret.
    ///
    /// Omitted from default `Serialize` (use the wasm-bindgen getter for the
    /// intentional secret-returning API).
    #[serde(skip_serializing)]
    pub private_key: String,
    /// Public key as x-only hex string (64 hex chars, no 0x prefix)
    pub public_key: String,
}

impl fmt::Debug for WasmNostrKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmNostrKeypair")
            .field("private_key", &"***")
            .field("public_key", &self.public_key)
            .finish()
    }
}

#[wasm_bindgen]
impl WasmNostrKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new(private_key: String, public_key: String) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

/// Public-only Nostr key (x-only, BIP-340). No private key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmNostrPublicKey {
    /// Public key as x-only hex string (64 hex chars, no 0x prefix)
    pub public_key: String,
}

#[wasm_bindgen]
impl WasmNostrPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: String) -> Self {
        Self { public_key }
    }
}

/// Stark ECDSA signature result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmStarkSignature {
    /// Signature r component (hex)
    pub r: String,
    /// Signature s component (hex)
    pub s: String,
    /// Public key (hex)
    #[wasm_bindgen(js_name = "publicKey")]
    pub public_key: String,
}

/// Nostr BIP-340 Schnorr signature result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmNostrSignature {
    /// x-only public key (64 hex chars, no 0x prefix)
    #[wasm_bindgen(js_name = "publicKey")]
    pub public_key: String,
    /// BIP-340 signature (128 hex chars, no 0x prefix)
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_point_validation_rejects_invalid_hex() {
        assert!(WasmPoint {
            x: "not-hex".to_string(),
            y: "0x1".to_string(),
        }
        .validate()
        .is_err());
    }

    #[test]
    fn wasm_point_try_from_rejects_invalid_coordinates() {
        let error = krusty_kms_common::SerializablePoint::try_from(WasmPoint {
            x: "0x1".to_string(),
            y: "not-hex".to_string(),
        })
        .unwrap_err();
        assert!(matches!(error, WasmError::SerializationError(_)));
    }

    #[test]
    fn wasm_account_state_total_balance_rejects_overflow() {
        let state = WasmAccountState {
            balance: u128::MAX.to_string(),
            pending_balance: "1".to_string(),
            nonce: 0,
        };
        assert!(matches!(
            state.checked_total_balance(),
            Err(WasmError::InvalidAmount(_))
        ));
    }

    #[test]
    fn wasm_keypair_debug_redacts_private_key() {
        let kp = WasmKeypair::new(
            "0xdeadbeef".to_string(),
            "0x1".to_string(),
            "0x2".to_string(),
        );
        let debug = format!("{kp:?}");
        assert!(debug.contains("***"));
        assert!(!debug.contains("deadbeef"));
    }

    #[test]
    fn wasm_nostr_keypair_debug_redacts_private_key() {
        let kp = WasmNostrKeypair::new("aabbccdd".to_string(), "11223344".to_string());
        let debug = format!("{kp:?}");
        assert!(debug.contains("***"));
        assert!(!debug.contains("aabbccdd"));
    }
}

// Note: Parameter types (WasmFundParams, WasmTransferParams, etc.) and
// proof result types are defined in proof.rs with complete fields.
