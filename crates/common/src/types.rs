//! Common type definitions for TONGO protocol.

use serde::{Deserialize, Serialize};
use starknet_types_core::curve::{AffinePoint, ProjectivePoint};
use starknet_types_core::felt::Felt;

/// Represents a point on the Stark curve in serializable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializablePoint {
    pub x: String,
    pub y: String,
}

impl SerializablePoint {
    pub fn from_affine(point: &AffinePoint) -> Self {
        Self {
            x: format!("{:#x}", point.x()),
            y: format!("{:#x}", point.y()),
        }
    }

    /// Converts a projective point to a serializable point.
    ///
    /// # Errors
    /// Returns `KmsError::PointAtInfinity` if the point is at infinity.
    pub fn try_from_projective(point: &ProjectivePoint) -> crate::Result<Self> {
        let affine = point
            .to_affine()
            .map_err(|_| crate::KmsError::PointAtInfinity)?;
        Ok(Self::from_affine(&affine))
    }

    /// Converts a projective point to a serializable point.
    ///
    /// # Panics
    /// Panics if the point is at infinity. Use `try_from_projective` for fallible conversion.
    #[deprecated(
        since = "0.2.0",
        note = "Use try_from_projective for fallible conversion"
    )]
    pub fn from_projective(point: &ProjectivePoint) -> Self {
        Self::try_from_projective(point).expect("Point at infinity cannot be serialized")
    }

    pub fn to_affine(&self) -> crate::Result<AffinePoint> {
        let x = Felt::from_hex(&self.x)
            .map_err(|e| crate::KmsError::DeserializationError(e.to_string()))?;
        let y = Felt::from_hex(&self.y)
            .map_err(|e| crate::KmsError::DeserializationError(e.to_string()))?;

        AffinePoint::new(x, y)
            .map_err(|e| crate::KmsError::InvalidPublicKey(format!("Invalid point: {:?}", e)))
    }
}

/// Proof of Exponentiation (PoE) proof structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoeProof {
    #[serde(rename = "A")]
    pub a: SerializablePoint,
    pub s: String,
    pub c: String,
}

/// Proof of Exponentiation 2 (PoE2) proof structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Poe2Proof {
    #[serde(rename = "A")]
    pub a: SerializablePoint,
    pub s1: String,
    pub s2: String,
    pub c: String,
}

/// ElGamal encryption proof structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalProof {
    #[serde(rename = "AL")]
    pub al: SerializablePoint,
    #[serde(rename = "AR")]
    pub ar: SerializablePoint,
    pub sb: String,
    pub sr: String,
    pub c: String,
}

/// Audit proof structure (SameEncryptUnknownRandom protocol).
/// Proves that two ciphertexts encrypt the same plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditProof {
    #[serde(rename = "Ax")]
    pub ax: SerializablePoint,
    #[serde(rename = "AL0")]
    pub al0: SerializablePoint,
    #[serde(rename = "AL1")]
    pub al1: SerializablePoint,
    #[serde(rename = "AR1")]
    pub ar1: SerializablePoint,
    pub sx: String,
    pub sb: String,
    pub sr: String,
    pub c: String,
}

/// ElGamal ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    pub l: ProjectivePoint,
    pub r: ProjectivePoint,
}

/// Tongo account state.
#[derive(Debug, Clone, Default)]
pub struct AccountState {
    /// Available balance (can be spent immediately)
    pub balance: u128,
    /// Pending balance (requires rollover)
    pub pending_balance: u128,
    /// Nonce for replay protection
    pub nonce: u64,
}

/// Transaction types in TONGO protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionType {
    Fund,
    Send,
    Rollover,
    Withdraw,
}

/// Proof of Bit (proves a committed value is either 0 or 1).
/// This is an OR proof: either V = h^r (bit=0) OR V/g = h^r (bit=1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfBit {
    #[serde(rename = "A0")]
    pub a0: SerializablePoint,
    #[serde(rename = "A1")]
    pub a1: SerializablePoint,
    pub c0: String,
    pub s0: String,
    pub s1: String,
}

/// Range proof structure proving a value is in [0, 2^bit_size - 1].
/// Contains commitments V_i = g^b_i * h^r_i for each bit and corresponding proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    pub commitments: Vec<SerializablePoint>,
    pub proofs: Vec<ProofOfBit>,
}

/// Proof of Transfer structure matching Cairo contract expectations.
/// This proves:
/// 1. Knowledge of private key (A_x, s_x)
/// 2. Correct encryption for recipient and self (A_b, A_bar, s_b, s_r)
/// 3. Transfer amount is in valid range (range, R_aux)
/// 4. Leftover balance is in valid range (range2, R_aux2)
/// 5. Balance equations verify correctly (A_b2, s_b2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfTransfer {
    #[serde(rename = "A_x")]
    pub a_x: SerializablePoint,
    #[serde(rename = "A_r")]
    pub a_r: SerializablePoint,
    #[serde(rename = "A_r2")]
    pub a_r2: SerializablePoint,
    #[serde(rename = "A_b")]
    pub a_b: SerializablePoint,
    #[serde(rename = "A_b2")]
    pub a_b2: SerializablePoint,
    #[serde(rename = "A_v")]
    pub a_v: SerializablePoint,
    #[serde(rename = "A_v2")]
    pub a_v2: SerializablePoint,
    #[serde(rename = "A_bar")]
    pub a_bar: SerializablePoint,
    pub s_x: String,
    pub s_r: String,
    pub s_b: String,
    pub s_b2: String,
    pub s_r2: String,
    pub range: Range,
    pub range2: Range,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serializable_point_from_affine() {
        // Use valid generator point coordinates
        let x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let affine = AffinePoint::new(x, y).unwrap();
        let point = SerializablePoint::from_affine(&affine);
        assert!(point.x.starts_with("0x"));
        assert!(point.y.starts_with("0x"));
    }

    #[test]
    fn test_serializable_point_try_from_projective() {
        // Use the generator point which is always valid
        let g_x =
            Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
                .unwrap();
        let g_y =
            Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
                .unwrap();
        let projective = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        let result = SerializablePoint::try_from_projective(&projective);
        assert!(result.is_ok());
        let point = result.unwrap();
        assert!(point.x.starts_with("0x"));
        assert!(point.y.starts_with("0x"));
    }

    #[test]
    fn test_serializable_point_try_from_projective_identity() {
        // Identity point (point at infinity) should fail
        let identity = ProjectivePoint::identity();
        let result = SerializablePoint::try_from_projective(&identity);
        assert!(result.is_err());
    }

    #[test]
    fn test_serializable_point_to_affine() {
        // Use valid generator point coordinates
        let point = SerializablePoint {
            x: "0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca".to_string(),
            y: "0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f".to_string(),
        };
        let affine = point.to_affine().unwrap();
        assert_eq!(
            affine.x(),
            Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
                .unwrap()
        );
    }

    #[test]
    fn test_serializable_point_to_affine_invalid_hex() {
        let point = SerializablePoint {
            x: "invalid_hex".to_string(),
            y: "0x2".to_string(),
        };
        let result = point.to_affine();
        assert!(result.is_err());
    }

    #[test]
    fn test_serializable_point_roundtrip() {
        // Create a valid point, serialize, deserialize
        let g_x =
            Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
                .unwrap();
        let g_y =
            Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
                .unwrap();
        let original = AffinePoint::new(g_x, g_y).unwrap();

        let serialized = SerializablePoint::from_affine(&original);
        let recovered = serialized.to_affine().unwrap();

        assert_eq!(original.x(), recovered.x());
        assert_eq!(original.y(), recovered.y());
    }
}
