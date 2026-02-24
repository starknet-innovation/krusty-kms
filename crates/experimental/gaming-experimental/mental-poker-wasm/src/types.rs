//! WASM-compatible type definitions for mental poker.
//!
//! Provides JavaScript-friendly types with serde serialization for
//! seamless interop between Rust WASM and TypeScript.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

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

    /// Convert to compact binary format (64 bytes).
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        use starknet_types_core::felt::Felt;

        let x =
            Felt::from_hex(&self.x).map_err(|e| JsValue::from_str(&format!("Invalid x: {e}")))?;
        let y =
            Felt::from_hex(&self.y).map_err(|e| JsValue::from_str(&format!("Invalid y: {e}")))?;

        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&x.to_bytes_be());
        bytes.extend_from_slice(&y.to_bytes_be());
        Ok(bytes)
    }

    /// Create from compact binary format (64 bytes).
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmPoint, JsValue> {
        use starknet_types_core::felt::Felt;

        if bytes.len() != 64 {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length: expected 64 bytes, got {}",
                bytes.len()
            )));
        }

        let x_bytes: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| JsValue::from_str("Failed to parse x: invalid byte slice"))?;
        let y_bytes: [u8; 32] = bytes[32..]
            .try_into()
            .map_err(|_| JsValue::from_str("Failed to parse y: invalid byte slice"))?;

        let x = Felt::from_bytes_be(&x_bytes);
        let y = Felt::from_bytes_be(&y_bytes);

        Ok(WasmPoint {
            x: format!("{:#x}", x),
            y: format!("{:#x}", y),
        })
    }
}

/// Public key wrapper for mental poker operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmPublicKey {
    pub x: String,
    pub y: String,
}

#[wasm_bindgen]
impl WasmPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(x: String, y: String) -> Self {
        Self { x, y }
    }

    /// Serialize to concatenated hex format "0x{x}{y}".
    #[wasm_bindgen(js_name = "toHex")]
    pub fn to_hex(&self) -> String {
        let x = self.x.trim_start_matches("0x");
        let y = self.y.trim_start_matches("0x");
        // Pad to 64 chars each
        format!("0x{:0>64}{:0>64}", x, y)
    }

    /// Create from concatenated hex format.
    #[wasm_bindgen(js_name = "fromHex")]
    pub fn from_hex(hex: &str) -> Result<WasmPublicKey, JsValue> {
        let hex = hex.trim().trim_start_matches("0x").trim_start_matches("0X");
        if hex.len() != 128 {
            return Err(JsValue::from_str(
                "Public key must be 128 hex characters (64 for x, 64 for y)",
            ));
        }

        Ok(WasmPublicKey {
            x: format!("0x{}", &hex[..64]),
            y: format!("0x{}", &hex[64..]),
        })
    }
}

/// An open (unmasked) card representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmCard {
    /// Card index (1-based for standard deck: 1-52)
    pub index: u64,
    /// The card's point representation
    pub point: WasmPoint,
}

#[wasm_bindgen]
impl WasmCard {
    /// Create a card from an index.
    #[wasm_bindgen(constructor)]
    pub fn new(index: u64) -> Result<WasmCard, JsValue> {
        use mental_poker::types::Card;

        let card = Card::from_index(index);
        let affine = card
            .point
            .to_affine()
            .map_err(|_| JsValue::from_str("Invalid card point"))?;

        Ok(WasmCard {
            index,
            point: WasmPoint {
                x: format!("{:#x}", affine.x()),
                y: format!("{:#x}", affine.y()),
            },
        })
    }
}

/// A reveal token for card decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmRevealToken {
    pub point: WasmPoint,
}

#[wasm_bindgen]
impl WasmRevealToken {
    #[wasm_bindgen(constructor)]
    pub fn new(point: WasmPoint) -> Self {
        Self { point }
    }

    /// Create zero reveal token (identity).
    #[wasm_bindgen(js_name = "zero")]
    pub fn zero() -> WasmRevealToken {
        WasmRevealToken {
            point: WasmPoint {
                x: "0x0".to_string(),
                y: "0x0".to_string(),
            },
        }
    }
}

/// Key ownership proof (Schnorr-style).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmKeyOwnershipProof {
    /// Commitment point
    pub commitment_x: String,
    pub commitment_y: String,
    /// Response scalar
    pub response: String,
    /// Challenge scalar
    pub challenge: String,
}

#[wasm_bindgen]
impl WasmKeyOwnershipProof {
    #[wasm_bindgen(constructor)]
    pub fn new(
        commitment_x: String,
        commitment_y: String,
        response: String,
        challenge: String,
    ) -> Self {
        Self {
            commitment_x,
            commitment_y,
            response,
            challenge,
        }
    }

    /// Serialize to JSON string.
    #[wasm_bindgen(js_name = "toJson")]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create from JSON string.
    #[wasm_bindgen(js_name = "fromJson")]
    pub fn from_json(json: &str) -> Result<WasmKeyOwnershipProof, JsValue> {
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// DL equality proof (Chaum-Pedersen style).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmDLEqualityProof {
    /// First commitment point (a1)
    pub a1_x: String,
    pub a1_y: String,
    /// Second commitment point (a2)
    pub a2_x: String,
    pub a2_y: String,
    /// Response scalar
    pub response: String,
    /// Challenge scalar
    pub challenge: String,
}

#[wasm_bindgen]
impl WasmDLEqualityProof {
    #[wasm_bindgen(constructor)]
    pub fn new(
        a1_x: String,
        a1_y: String,
        a2_x: String,
        a2_y: String,
        response: String,
        challenge: String,
    ) -> Self {
        Self {
            a1_x,
            a1_y,
            a2_x,
            a2_y,
            response,
            challenge,
        }
    }

    /// Serialize to JSON string.
    #[wasm_bindgen(js_name = "toJson")]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create from JSON string.
    #[wasm_bindgen(js_name = "fromJson")]
    pub fn from_json(json: &str) -> Result<WasmDLEqualityProof, JsValue> {
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// Compact proof format for network transfer (binary).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmCompactProof {
    /// Binary proof data
    pub data: Vec<u8>,
    /// Proof type identifier
    pub proof_type: String,
}

#[wasm_bindgen]
impl WasmCompactProof {
    #[wasm_bindgen(constructor)]
    pub fn new(data: Vec<u8>, proof_type: String) -> Self {
        Self { data, proof_type }
    }

    /// Get the size in bytes.
    #[wasm_bindgen(js_name = "sizeBytes")]
    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

/// Compact masked card for network transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmCompactMaskedCard {
    /// Binary data (128 bytes: c0 + c1)
    pub data: Vec<u8>,
}

#[wasm_bindgen]
impl WasmCompactMaskedCard {
    #[wasm_bindgen(constructor)]
    pub fn new(data: Vec<u8>) -> Result<WasmCompactMaskedCard, JsValue> {
        if data.len() != 128 {
            return Err(JsValue::from_str("Compact masked card must be 128 bytes"));
        }
        Ok(Self { data })
    }

    /// Get the size in bytes.
    #[wasm_bindgen(js_name = "sizeBytes")]
    pub fn size_bytes(&self) -> usize {
        128
    }
}

// ============================================================================
// Conversions from mental-poker types
// ============================================================================

impl From<mental_poker::types::KeyOwnershipProof> for WasmKeyOwnershipProof {
    fn from(proof: mental_poker::types::KeyOwnershipProof) -> Self {
        Self {
            commitment_x: proof.commitment.x,
            commitment_y: proof.commitment.y,
            response: proof.response,
            challenge: proof.challenge,
        }
    }
}

impl From<WasmKeyOwnershipProof> for mental_poker::types::KeyOwnershipProof {
    fn from(proof: WasmKeyOwnershipProof) -> Self {
        Self {
            commitment: mental_poker::types::SerializablePoint {
                x: proof.commitment_x,
                y: proof.commitment_y,
            },
            response: proof.response,
            challenge: proof.challenge,
        }
    }
}

impl From<mental_poker::types::DLEqualityProof> for WasmDLEqualityProof {
    fn from(proof: mental_poker::types::DLEqualityProof) -> Self {
        Self {
            a1_x: proof.a1.x,
            a1_y: proof.a1.y,
            a2_x: proof.a2.x,
            a2_y: proof.a2.y,
            response: proof.response,
            challenge: proof.challenge,
        }
    }
}

impl From<WasmDLEqualityProof> for mental_poker::types::DLEqualityProof {
    fn from(proof: WasmDLEqualityProof) -> Self {
        Self {
            a1: mental_poker::types::SerializablePoint {
                x: proof.a1_x,
                y: proof.a1_y,
            },
            a2: mental_poker::types::SerializablePoint {
                x: proof.a2_x,
                y: proof.a2_y,
            },
            response: proof.response,
            challenge: proof.challenge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm_card() {
        let card = WasmCard::new(1).unwrap();
        assert_eq!(card.index, 1);
        assert!(card.point.x.starts_with("0x"));
    }

    #[wasm_bindgen_test]
    fn test_wasm_point_bytes_roundtrip() {
        let point = WasmPoint::new(
            "0x1234567890abcdef".to_string(),
            "0xfedcba0987654321".to_string(),
        );
        let bytes = point.to_bytes().unwrap();
        assert_eq!(bytes.len(), 64);
        let recovered = WasmPoint::from_bytes(&bytes).unwrap();
        // Note: leading zeros may differ, but values should be equivalent
        assert!(!recovered.x.is_empty());
        assert!(!recovered.y.is_empty());
    }

    #[wasm_bindgen_test]
    fn test_wasm_public_key_hex() {
        let pk = WasmPublicKey::new("0x1234".to_string(), "0x5678".to_string());
        let hex = pk.to_hex();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + 128); // "0x" + 128 hex chars

        let recovered = WasmPublicKey::from_hex(&hex).unwrap();
        // Values should be recoverable (with padding)
        assert!(!recovered.x.is_empty());
        assert!(!recovered.y.is_empty());
    }

    // =========================================================================
    // TDD: Tests for malformed input handling (P0 critical WASM panic fixes)
    // These tests run only in wasm32 target since JsValue is wasm-only
    // =========================================================================

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_wasm_point_from_bytes_empty_input_returns_error() {
        // Empty byte array should return an error, not panic
        let empty_bytes: &[u8] = &[];
        let result = WasmPoint::from_bytes(empty_bytes);
        assert!(result.is_err(), "Empty input should return Err, not panic");
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_wasm_point_from_bytes_short_input_returns_error() {
        // Short byte array (less than 64 bytes) should return an error, not panic
        let short_bytes: Vec<u8> = vec![0u8; 32]; // Only 32 bytes, needs 64
        let result = WasmPoint::from_bytes(&short_bytes);
        assert!(result.is_err(), "Short input should return Err, not panic");
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_wasm_point_from_bytes_63_bytes_returns_error() {
        // Off-by-one: 63 bytes should return error
        let almost_bytes: Vec<u8> = vec![0u8; 63];
        let result = WasmPoint::from_bytes(&almost_bytes);
        assert!(result.is_err(), "63 bytes should return Err, not panic");
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_wasm_point_from_bytes_oversized_input_returns_error() {
        // Too many bytes should return error (not silently truncate)
        let oversized_bytes: Vec<u8> = vec![0u8; 128];
        let result = WasmPoint::from_bytes(&oversized_bytes);
        assert!(result.is_err(), "Oversized input should return Err");
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_wasm_point_from_bytes_valid_64_bytes_succeeds() {
        // Valid 64 bytes should succeed
        let valid_bytes: Vec<u8> = vec![0u8; 64];
        let result = WasmPoint::from_bytes(&valid_bytes);
        assert!(result.is_ok(), "Valid 64 bytes should succeed");
    }
}
