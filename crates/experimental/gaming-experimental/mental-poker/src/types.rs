//! Core type definitions for the mental poker protocol.
//!
//! This module defines the fundamental types used throughout the protocol:
//! - Cards (open and masked)
//! - Keys (player and aggregate)
//! - Proofs (various ZK proofs)
//! - Protocol parameters

use krusty_kms_crypto::StarkCurve;
use serde::{Deserialize, Serialize};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// An open (unmasked) playing card.
///
/// In the discrete-log based implementation, a card is represented as a point
/// on the elliptic curve. This is essentially an ElGamal plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// The curve point representing this card
    pub point: ProjectivePoint,
}

impl Card {
    /// Create a new card from a curve point.
    pub fn new(point: ProjectivePoint) -> Self {
        Self { point }
    }

    /// Create a card from a scalar (card index).
    ///
    /// Maps a card index to a unique curve point: card = g^index
    ///
    /// # Note
    /// This method does not validate that index != 0. For validated creation,
    /// use `try_from_index` instead.
    pub fn from_index(index: u64) -> Self {
        let scalar = Felt::from(index);
        let point = StarkCurve::mul_generator(&scalar);
        Self { point }
    }

    /// Create a card from a scalar (card index) with validation.
    ///
    /// Maps a card index to a unique curve point: card = g^index
    ///
    /// # Errors
    /// Returns `InvalidCardIndex` if index is 0 (would produce identity point).
    ///
    /// # Example
    /// ```
    /// use mental_poker::Card;
    ///
    /// // Valid indices work
    /// let card = Card::try_from_index(1).unwrap();
    ///
    /// // Index 0 is rejected
    /// assert!(Card::try_from_index(0).is_err());
    /// ```
    pub fn try_from_index(index: u64) -> crate::error::Result<Self> {
        if index == 0 {
            return Err(crate::error::MentalPokerError::InvalidCardIndex(
                "card index 0 produces identity point which is invalid".to_string(),
            ));
        }
        let scalar = Felt::from(index);
        let point = StarkCurve::mul_generator(&scalar);
        Ok(Self { point })
    }

    /// Create a random card (for testing/setup).
    pub fn random() -> Self {
        let scalar = krusty_kms_crypto::scalar::random_felt();
        let point = StarkCurve::mul_generator(&scalar);
        Self { point }
    }
}

/// A masked (encrypted) playing card.
///
/// This is an ElGamal ciphertext consisting of two curve points (c0, c1).
/// The card is encrypted under the aggregate public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedCard {
    /// First component: g^r (randomness commitment)
    pub c0: ProjectivePoint,
    /// Second component: card + pk^r (encrypted card)
    pub c1: ProjectivePoint,
}

impl MaskedCard {
    /// Create a new masked card from ciphertext components.
    pub fn new(c0: ProjectivePoint, c1: ProjectivePoint) -> Self {
        Self { c0, c1 }
    }

    /// Add two masked cards (homomorphic addition).
    pub fn add(&self, other: &MaskedCard) -> MaskedCard {
        MaskedCard {
            c0: StarkCurve::add(&self.c0, &other.c0),
            c1: StarkCurve::add(&self.c1, &other.c1),
        }
    }

    /// Negate a masked card.
    pub fn negate(&self) -> crate::error::Result<MaskedCard> {
        use crate::utils::negate_point;
        Ok(MaskedCard {
            c0: negate_point(&self.c0)?,
            c1: negate_point(&self.c1)?,
        })
    }

    /// Scalar multiply a masked card.
    pub fn scalar_mul(&self, scalar: &Felt) -> MaskedCard {
        MaskedCard {
            c0: StarkCurve::mul(scalar, Some(&self.c0)),
            c1: StarkCurve::mul(scalar, Some(&self.c1)),
        }
    }
}

/// A reveal token for partial decryption.
///
/// Each player computes a reveal token for cards they want to help reveal.
/// The token is: token = c0^sk where sk is the player's secret key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealToken {
    /// The reveal token point
    pub point: ProjectivePoint,
}

impl RevealToken {
    /// Create a new reveal token.
    pub fn new(point: ProjectivePoint) -> Self {
        Self { point }
    }

    /// Create zero reveal token (identity).
    pub fn zero() -> Self {
        Self {
            point: ProjectivePoint::identity(),
        }
    }

    /// Add two reveal tokens.
    pub fn add(&self, other: &RevealToken) -> RevealToken {
        RevealToken {
            point: StarkCurve::add(&self.point, &other.point),
        }
    }
}

/// A player's public key.
///
/// This is a curve point: pk = g^sk
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// The public key point
    pub point: ProjectivePoint,
}

impl PublicKey {
    /// Create a new public key.
    pub fn new(point: ProjectivePoint) -> Self {
        Self { point }
    }

    /// Create identity (zero) public key.
    pub fn zero() -> Self {
        Self {
            point: ProjectivePoint::identity(),
        }
    }

    /// Add two public keys (for key aggregation).
    pub fn add(&self, other: &PublicKey) -> PublicKey {
        PublicKey {
            point: StarkCurve::add(&self.point, &other.point),
        }
    }
}

/// A player's secret key.
///
/// This is a scalar value in the curve's scalar field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey {
    /// The secret key scalar
    pub scalar: Felt,
}

impl SecretKey {
    /// Create a new secret key.
    pub fn new(scalar: Felt) -> Self {
        Self { scalar }
    }

    /// Generate a random secret key.
    pub fn random() -> Self {
        Self {
            scalar: krusty_kms_crypto::scalar::random_felt(),
        }
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        let point = StarkCurve::mul_generator(&self.scalar);
        PublicKey::new(point)
    }
}

/// Protocol parameters for the mental poker protocol.
#[derive(Debug, Clone)]
pub struct Parameters {
    /// Number of rows in the deck matrix (m)
    pub m: usize,
    /// Number of columns in the deck matrix (n)
    pub n: usize,
    /// Total number of cards (m * n)
    pub num_cards: usize,
    /// Generator point G
    pub generator: ProjectivePoint,
    /// Second generator point H (for commitments)
    pub generator_h: ProjectivePoint,
}

impl Parameters {
    /// Create new protocol parameters.
    ///
    /// # Arguments
    /// * `m` - Number of rows in deck matrix
    /// * `n` - Number of columns in deck matrix
    pub fn new(m: usize, n: usize) -> Self {
        Self {
            m,
            n,
            num_cards: m * n,
            generator: StarkCurve::generator(),
            generator_h: StarkCurve::generator_h(),
        }
    }

    /// Create parameters for a standard 52-card deck.
    pub fn standard_deck() -> Self {
        // 4 suits x 13 values = 52 cards
        Self::new(4, 13)
    }
}

/// Schnorr proof of key ownership.
///
/// Proves knowledge of sk such that pk = g^sk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyOwnershipProof {
    /// Commitment: a = g^r
    pub commitment: SerializablePoint,
    /// Response: s = r + c*sk
    pub response: String,
    /// Challenge: c = H(g, pk, a)
    pub challenge: String,
}

/// Chaum-Pedersen proof of discrete log equality.
///
/// Proves that log_g(y1) = log_h(y2) for some common exponent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLEqualityProof {
    /// Commitment to g: a1 = g^r
    pub a1: SerializablePoint,
    /// Commitment to h: a2 = h^r
    pub a2: SerializablePoint,
    /// Response: s = r + c*x
    pub response: String,
    /// Challenge
    pub challenge: String,
}

/// A serializable point representation (hex string format for JSON compatibility).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerializablePoint {
    pub x: String,
    pub y: String,
}

impl SerializablePoint {
    /// Create from a projective point.
    pub fn from_projective(point: &ProjectivePoint) -> crate::error::Result<Self> {
        let affine = StarkCurve::projective_to_affine(point)?;
        Ok(Self {
            x: format!("{:#x}", affine.x()),
            y: format!("{:#x}", affine.y()),
        })
    }

    /// Convert to projective point.
    pub fn to_projective(&self) -> crate::error::Result<ProjectivePoint> {
        let x = Felt::from_hex(&self.x)
            .map_err(|e| crate::error::MentalPokerError::SerializationError(e.to_string()))?;
        let y = Felt::from_hex(&self.y)
            .map_err(|e| crate::error::MentalPokerError::SerializationError(e.to_string()))?;
        ProjectivePoint::from_affine(x, y).map_err(|_| crate::error::MentalPokerError::InvalidPoint)
    }

    /// Convert to compact binary format.
    pub fn to_bytes(&self) -> crate::error::Result<CompactPoint> {
        let x = Felt::from_hex(&self.x)
            .map_err(|e| crate::error::MentalPokerError::SerializationError(e.to_string()))?;
        let y = Felt::from_hex(&self.y)
            .map_err(|e| crate::error::MentalPokerError::SerializationError(e.to_string()))?;
        Ok(CompactPoint {
            x: x.to_bytes_be(),
            y: y.to_bytes_be(),
        })
    }

    /// Create from compact binary format.
    pub fn from_bytes(compact: &CompactPoint) -> crate::error::Result<Self> {
        let x = Felt::from_bytes_be(&compact.x);
        let y = Felt::from_bytes_be(&compact.y);
        Ok(Self {
            x: format!("{:#x}", x),
            y: format!("{:#x}", y),
        })
    }
}

/// Compact binary representation of a curve point (64 bytes total).
///
/// This is more efficient than hex string serialization for network/storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactPoint {
    /// X coordinate as 32 bytes (big-endian)
    #[serde(with = "serde_bytes_array")]
    pub x: [u8; 32],
    /// Y coordinate as 32 bytes (big-endian)
    #[serde(with = "serde_bytes_array")]
    pub y: [u8; 32],
}

impl CompactPoint {
    /// Create from a projective point.
    pub fn from_projective(point: &ProjectivePoint) -> crate::error::Result<Self> {
        let affine = StarkCurve::projective_to_affine(point)?;
        Ok(Self {
            x: affine.x().to_bytes_be(),
            y: affine.y().to_bytes_be(),
        })
    }

    /// Convert to projective point.
    pub fn to_projective(&self) -> crate::error::Result<ProjectivePoint> {
        let x = Felt::from_bytes_be(&self.x);
        let y = Felt::from_bytes_be(&self.y);
        ProjectivePoint::from_affine(x, y).map_err(|_| crate::error::MentalPokerError::InvalidPoint)
    }

    /// Get the raw bytes (64 bytes: x || y).
    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.x);
        bytes[32..].copy_from_slice(&self.y);
        bytes
    }

    /// Create from raw bytes (64 bytes: x || y).
    pub fn from_raw_bytes(bytes: &[u8; 64]) -> Self {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[..32]);
        y.copy_from_slice(&bytes[32..]);
        Self { x, y }
    }
}

/// Compact scalar representation (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactScalar(#[serde(with = "serde_bytes_array")] pub [u8; 32]);

impl CompactScalar {
    /// Create from a Felt.
    pub fn from_felt(felt: &Felt) -> Self {
        Self(felt.to_bytes_be())
    }

    /// Convert to Felt.
    pub fn to_felt(&self) -> Felt {
        Felt::from_bytes_be(&self.0)
    }

    /// Create from hex string.
    pub fn from_hex(hex: &str) -> crate::error::Result<Self> {
        let felt = Felt::from_hex(hex)
            .map_err(|e| crate::error::MentalPokerError::SerializationError(e.to_string()))?;
        Ok(Self::from_felt(&felt))
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        format!("{:#x}", self.to_felt())
    }
}

/// Helper module for serializing fixed-size byte arrays with serde.
mod serde_bytes_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte array length"))
    }
}

/// Compact binary DL equality proof.
///
/// This is more efficient than the string-based `DLEqualityProof` for
/// network transmission and storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactDLEqualityProof {
    /// Commitment to g: a1 = g^r
    pub a1: CompactPoint,
    /// Commitment to h: a2 = h^r
    pub a2: CompactPoint,
    /// Response: s = r + c*x
    pub response: CompactScalar,
    /// Challenge
    pub challenge: CompactScalar,
}

impl CompactDLEqualityProof {
    /// Convert from string-based proof.
    pub fn from_proof(proof: &DLEqualityProof) -> crate::error::Result<Self> {
        Ok(Self {
            a1: proof.a1.to_bytes()?,
            a2: proof.a2.to_bytes()?,
            response: CompactScalar::from_hex(&proof.response)?,
            challenge: CompactScalar::from_hex(&proof.challenge)?,
        })
    }

    /// Convert to string-based proof.
    pub fn to_proof(&self) -> crate::error::Result<DLEqualityProof> {
        Ok(DLEqualityProof {
            a1: SerializablePoint::from_bytes(&self.a1)?,
            a2: SerializablePoint::from_bytes(&self.a2)?,
            response: self.response.to_hex(),
            challenge: self.challenge.to_hex(),
        })
    }

    /// Get total size in bytes (2 points + 2 scalars = 192 bytes).
    pub const fn size_bytes() -> usize {
        64 + 64 + 32 + 32 // 192 bytes
    }
}

/// Compact binary key ownership proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactKeyOwnershipProof {
    /// Commitment: a = g^r
    pub commitment: CompactPoint,
    /// Response: s = r + c*sk
    pub response: CompactScalar,
    /// Challenge: c = H(g, pk, a)
    pub challenge: CompactScalar,
}

impl CompactKeyOwnershipProof {
    /// Convert from string-based proof.
    pub fn from_proof(proof: &KeyOwnershipProof) -> crate::error::Result<Self> {
        Ok(Self {
            commitment: proof.commitment.to_bytes()?,
            response: CompactScalar::from_hex(&proof.response)?,
            challenge: CompactScalar::from_hex(&proof.challenge)?,
        })
    }

    /// Convert to string-based proof.
    pub fn to_proof(&self) -> crate::error::Result<KeyOwnershipProof> {
        Ok(KeyOwnershipProof {
            commitment: SerializablePoint::from_bytes(&self.commitment)?,
            response: self.response.to_hex(),
            challenge: self.challenge.to_hex(),
        })
    }

    /// Get total size in bytes (1 point + 2 scalars = 128 bytes).
    pub const fn size_bytes() -> usize {
        64 + 32 + 32 // 128 bytes
    }
}

/// Compact binary masked card representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactMaskedCard {
    /// First component: g^r
    pub c0: CompactPoint,
    /// Second component: card + pk^r
    pub c1: CompactPoint,
}

impl CompactMaskedCard {
    /// Convert from MaskedCard.
    pub fn from_masked_card(card: &MaskedCard) -> crate::error::Result<Self> {
        Ok(Self {
            c0: CompactPoint::from_projective(&card.c0)?,
            c1: CompactPoint::from_projective(&card.c1)?,
        })
    }

    /// Convert to MaskedCard.
    pub fn to_masked_card(&self) -> crate::error::Result<MaskedCard> {
        Ok(MaskedCard {
            c0: self.c0.to_projective()?,
            c1: self.c1.to_projective()?,
        })
    }

    /// Get total size in bytes (2 points = 128 bytes).
    pub const fn size_bytes() -> usize {
        64 + 64 // 128 bytes
    }
}

/// Compact binary reveal token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactRevealToken {
    /// The reveal token point
    pub point: CompactPoint,
}

impl CompactRevealToken {
    /// Convert from RevealToken.
    pub fn from_reveal_token(token: &RevealToken) -> crate::error::Result<Self> {
        Ok(Self {
            point: CompactPoint::from_projective(&token.point)?,
        })
    }

    /// Convert to RevealToken.
    pub fn to_reveal_token(&self) -> crate::error::Result<RevealToken> {
        Ok(RevealToken {
            point: self.point.to_projective()?,
        })
    }

    /// Get total size in bytes (1 point = 64 bytes).
    pub const fn size_bytes() -> usize {
        64
    }
}

/// A permutation for shuffling.
#[derive(Debug, Clone)]
pub struct Permutation {
    /// The permutation as an array of indices
    pub indices: Vec<usize>,
}

impl Permutation {
    /// Create a new permutation.
    pub fn new(indices: Vec<usize>) -> Self {
        Self { indices }
    }

    /// Generate a random permutation of size n.
    pub fn random(n: usize) -> Self {
        use rand::seq::SliceRandom;
        let mut indices: Vec<usize> = (0..n).collect();
        indices.shuffle(&mut rand::rng());
        Self { indices }
    }

    /// Apply the permutation to an array.
    pub fn permute<T: Clone>(&self, arr: &[T]) -> Vec<T> {
        self.indices.iter().map(|&i| arr[i].clone()).collect()
    }

    /// Get the size of the permutation.
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Check if permutation is empty.
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_card_from_index() {
        let card1 = Card::from_index(1);
        let card2 = Card::from_index(2);
        assert_ne!(card1.point, card2.point);
    }

    #[test]
    fn test_secret_key_to_public_key() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        assert!(!StarkCurve::is_infinity(&pk.point));
    }

    #[test]
    fn test_public_key_aggregation() {
        let sk1 = SecretKey::random();
        let sk2 = SecretKey::random();
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();

        let aggregate = pk1.add(&pk2);
        assert!(!StarkCurve::is_infinity(&aggregate.point));
    }

    #[test]
    fn test_permutation() {
        let perm = Permutation::new(vec![2, 0, 1]);
        let arr = vec!["a", "b", "c"];
        let permuted = perm.permute(&arr);
        assert_eq!(permuted, vec!["c", "a", "b"]);
    }

    #[test]
    fn test_random_permutation() {
        let perm = Permutation::random(10);
        assert_eq!(perm.len(), 10);

        // Check it's a valid permutation (all indices present)
        let mut sorted = perm.indices.clone();
        sorted.sort();
        assert_eq!(sorted, (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn test_masked_card_operations() {
        let card = Card::from_index(1);
        let r = krusty_kms_crypto::scalar::random_felt();
        let pk = SecretKey::random().public_key();

        // Create a masked card manually
        let c0 = StarkCurve::mul_generator(&r);
        let pk_r = StarkCurve::mul(&r, Some(&pk.point));
        let c1 = StarkCurve::add(&card.point, &pk_r);
        let masked = MaskedCard::new(c0, c1);

        // Test scalar multiplication
        let two = Felt::from(2u64);
        let doubled = masked.scalar_mul(&two);
        assert!(!StarkCurve::is_infinity(&doubled.c0));
    }

    #[test]
    fn test_compact_point_roundtrip() {
        let point = StarkCurve::mul_generator(&Felt::from(42u64));
        let compact = CompactPoint::from_projective(&point).unwrap();
        let recovered = compact.to_projective().unwrap();
        assert_eq!(point, recovered);
    }

    #[test]
    fn test_compact_point_raw_bytes() {
        let point = StarkCurve::mul_generator(&Felt::from(123u64));
        let compact = CompactPoint::from_projective(&point).unwrap();
        let raw = compact.to_raw_bytes();
        let recovered = CompactPoint::from_raw_bytes(&raw);
        assert_eq!(compact, recovered);
    }

    #[test]
    fn test_compact_scalar_roundtrip() {
        let felt = Felt::from(0x123456789abcdef0u64);
        let compact = CompactScalar::from_felt(&felt);
        let recovered = compact.to_felt();
        assert_eq!(felt, recovered);
    }

    #[test]
    fn test_compact_scalar_hex_roundtrip() {
        let hex = "0x123456789abcdef0";
        let compact = CompactScalar::from_hex(hex).unwrap();
        let recovered_hex = compact.to_hex();
        // Compare the values, not the exact string format
        let original = Felt::from_hex(hex).unwrap();
        let recovered = Felt::from_hex(&recovered_hex).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_compact_masked_card_roundtrip() {
        let card = Card::from_index(1);
        let r = krusty_kms_crypto::scalar::random_felt();
        let pk = SecretKey::random().public_key();

        let c0 = StarkCurve::mul_generator(&r);
        let pk_r = StarkCurve::mul(&r, Some(&pk.point));
        let c1 = StarkCurve::add(&card.point, &pk_r);
        let masked = MaskedCard::new(c0, c1);

        let compact = CompactMaskedCard::from_masked_card(&masked).unwrap();
        let recovered = compact.to_masked_card().unwrap();
        assert_eq!(masked.c0, recovered.c0);
        assert_eq!(masked.c1, recovered.c1);
    }

    #[test]
    fn test_compact_reveal_token_roundtrip() {
        let point = StarkCurve::mul_generator(&krusty_kms_crypto::scalar::random_felt());
        let token = RevealToken::new(point);

        let compact = CompactRevealToken::from_reveal_token(&token).unwrap();
        let recovered = compact.to_reveal_token().unwrap();
        assert_eq!(token.point, recovered.point);
    }

    #[test]
    fn test_serializable_point_to_compact_roundtrip() {
        let point = StarkCurve::mul_generator(&Felt::from(999u64));
        let serializable = SerializablePoint::from_projective(&point).unwrap();
        let compact = serializable.to_bytes().unwrap();
        let recovered = SerializablePoint::from_bytes(&compact).unwrap();
        assert_eq!(serializable, recovered);
    }

    #[test]
    fn test_compact_types_size() {
        // Verify the size constants are accurate
        assert_eq!(CompactDLEqualityProof::size_bytes(), 192);
        assert_eq!(CompactKeyOwnershipProof::size_bytes(), 128);
        assert_eq!(CompactMaskedCard::size_bytes(), 128);
        assert_eq!(CompactRevealToken::size_bytes(), 64);
    }

    // Card index validation tests
    #[test]
    fn test_card_from_index_zero_should_fail() {
        // Card index 0 produces identity point (g^0 = identity), which is invalid
        let result = Card::try_from_index(0);
        assert!(result.is_err());
        match result {
            Err(crate::error::MentalPokerError::InvalidCardIndex(msg)) => {
                assert!(msg.contains("0"));
            }
            _ => panic!("Expected InvalidCardIndex error"),
        }
    }

    #[test]
    fn test_card_from_index_valid_indices() {
        // Valid indices should work
        let card1 = Card::try_from_index(1).expect("Index 1 should be valid");
        let card2 = Card::try_from_index(2).expect("Index 2 should be valid");
        let card52 = Card::try_from_index(52).expect("Index 52 should be valid");

        // Each should produce a distinct non-identity point
        assert_ne!(card1.point, card2.point);
        assert!(!StarkCurve::is_infinity(&card1.point));
        assert!(!StarkCurve::is_infinity(&card2.point));
        assert!(!StarkCurve::is_infinity(&card52.point));
    }

    #[test]
    fn test_card_from_index_boundary_max() {
        // Very large indices should still work (no upper bound in this design)
        let card_large = Card::try_from_index(u64::MAX).expect("Large index should be valid");
        assert!(!StarkCurve::is_infinity(&card_large.point));
    }

    #[test]
    fn test_card_from_index_produces_unique_points() {
        // Ensure different indices produce different cards
        let indices = [1u64, 2, 3, 10, 52, 100, 1000];
        let cards: Vec<_> = indices
            .iter()
            .map(|&i| Card::try_from_index(i).unwrap())
            .collect();

        // All points should be unique
        for i in 0..cards.len() {
            for j in (i + 1)..cards.len() {
                assert_ne!(
                    cards[i].point, cards[j].point,
                    "Cards with indices {} and {} should be different",
                    indices[i], indices[j]
                );
            }
        }
    }
}
