//! WASM-compatible type definitions.
//!
//! Provides JavaScript-friendly types with serde serialization for
//! seamless interop between Rust WASM and TypeScript.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

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
    pub fn new(balance: String, pending_balance: String, nonce: u64) -> Self {
        Self {
            balance,
            pending_balance,
            nonce,
        }
    }

    /// Get total balance (available + pending).
    #[wasm_bindgen(js_name = "totalBalance")]
    pub fn total_balance(&self) -> String {
        let balance: u128 = self.balance.parse().unwrap_or(0);
        let pending: u128 = self.pending_balance.parse().unwrap_or(0);
        balance.saturating_add(pending).to_string()
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

impl From<WasmAccountState> for krusty_kms_common::AccountState {
    fn from(state: WasmAccountState) -> Self {
        Self {
            balance: state.balance.parse().unwrap_or(0),
            pending_balance: state.pending_balance.parse().unwrap_or(0),
            nonce: state.nonce,
        }
    }
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
    pub fn new(x: String, y: String) -> Self {
        Self { x, y }
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

impl From<WasmPoint> for krusty_kms_common::SerializablePoint {
    fn from(p: WasmPoint) -> Self {
        Self {
            x: krusty_kms_common::utils::parse_hex_to_felt(&p.x)
                .expect("WasmPoint.x must be a valid felt hex string"),
            y: krusty_kms_common::utils::parse_hex_to_felt(&p.y)
                .expect("WasmPoint.y must be a valid felt hex string"),
        }
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

/// Keypair for TONGO operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmKeypair {
    /// Private key as hex string (0x-prefixed)
    pub private_key: String,
    /// Public key X coordinate as hex string
    pub public_key_x: String,
    /// Public key Y coordinate as hex string
    pub public_key_y: String,
}

#[wasm_bindgen]
impl WasmKeypair {
    #[wasm_bindgen(constructor)]
    pub fn new(private_key: String, public_key_x: String, public_key_y: String) -> Self {
        Self {
            private_key,
            public_key_x,
            public_key_y,
        }
    }

    /// Get the full public key as "0x{x}{y}" concatenated hex.
    #[wasm_bindgen(js_name = "publicKeyHex")]
    pub fn public_key_hex(&self) -> String {
        let x = self.public_key_x.trim_start_matches("0x");
        let y = self.public_key_y.trim_start_matches("0x");
        format!("0x{x}{y}")
    }
}

/// Transaction type enum for TONGO operations.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmNostrKeypair {
    /// Private key as hex string (64 hex chars, no 0x prefix)
    pub private_key: String,
    /// Public key as x-only hex string (64 hex chars, no 0x prefix)
    pub public_key: String,
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

// Note: Parameter types (WasmFundParams, WasmTransferParams, etc.) and
// proof result types are defined in proof.rs with complete fields.
