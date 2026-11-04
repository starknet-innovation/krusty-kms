//! Secp256k1 (Ethereum) signer for Starknet account transactions.
//!
//! OZ Ethereum account contracts expect a 5-Felt signature:
//! `[r_low, r_high, s_low, s_high, v]` where `r` and `s` are the secp256k1
//! ECDSA signature components encoded as u256 pairs, and `v` is the recovery
//! parity (0 or 1).

use k256::ecdsa::{SigningKey, VerifyingKey};
use krusty_kms_common::{KmsError, Result};
use starknet_types_core::felt::Felt;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A secp256k1 signer for Ethereum-key Starknet accounts.
///
/// Signs Starknet transaction hashes with secp256k1 ECDSA, producing the
/// 5-Felt signature format expected by OpenZeppelin Ethereum account contracts.
#[derive(ZeroizeOnDrop)]
pub struct EthSigner {
    signing_key: SigningKey,
}

impl EthSigner {
    /// Create from a raw 32-byte private key.
    pub fn from_private_key(bytes: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes.into())
            .map_err(|e| KmsError::InvalidPrivateKey(e.to_string()))?;
        Ok(Self { signing_key })
    }

    /// Create from a hex-encoded private key (with or without `0x` prefix).
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        // Both intermediate copies of the raw key are scrubbed before returning.
        let bytes = Zeroizing::new(hex::decode(hex_str)?);
        if bytes.len() != 32 {
            return Err(KmsError::InvalidPrivateKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&bytes);
        Self::from_private_key(&arr)
    }

    /// Get the uncompressed secp256k1 public key (65 bytes: `04 || x || y`).
    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        let verifying_key = VerifyingKey::from(&self.signing_key);
        let encoded = verifying_key.to_sec1_point(false);
        let bytes = encoded.as_bytes();
        let mut out = [0u8; 65];
        out.copy_from_slice(bytes);
        out
    }

    /// Get the public key as OZ Ethereum account constructor calldata.
    ///
    /// The OZ `EthAccount` constructor takes an `EthPublicKey`
    /// (`Secp256k1Point`), serialised as `(x: u256, y: u256)`; a Cairo `u256`
    /// serialises as `(low: u128, high: u128)`. The result is therefore
    /// `[x_low, x_high, y_low, y_high]`, taken straight from the 65-byte
    /// SEC1 encoding. No value passes through a `Felt` before it is split.
    pub fn public_key_calldata(&self) -> [Felt; 4] {
        let uncompressed = self.public_key_uncompressed();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        // Skip the 0x04 prefix byte
        x.copy_from_slice(&uncompressed[1..33]);
        y.copy_from_slice(&uncompressed[33..65]);
        let (x_low, x_high) = bytes32_to_u256_pair(&x);
        let (y_low, y_high) = bytes32_to_u256_pair(&y);
        [x_low, x_high, y_low, y_high]
    }

    /// Get the public key as its `(x, y)` secp256k1 coordinates.
    ///
    /// These are used in the OZ Eth account constructor calldata. Each
    /// coordinate is a full 256-bit value and is kept as 32 big-endian bytes:
    /// a `Felt` would reduce it modulo the Stark prime and change the key.
    /// Use [`EthCoordinate::to_u256_pair`] to encode it as calldata.
    pub fn public_key_xy(&self) -> (EthCoordinate, EthCoordinate) {
        let uncompressed = self.public_key_uncompressed();
        // Skip the 0x04 prefix byte
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&uncompressed[1..33]);
        y.copy_from_slice(&uncompressed[33..65]);
        (EthCoordinate(x), EthCoordinate(y))
    }

    /// Sign a Starknet transaction hash, producing the 5-Felt signature
    /// `[r_low, r_high, s_low, s_high, v]` expected by OZ Eth accounts.
    ///
    /// The hash is interpreted as 32 big-endian bytes and signed directly
    /// with secp256k1 ECDSA (prehash mode).
    pub fn sign_hash(&self, hash: &Felt) -> Result<[Felt; 5]> {
        let hash_bytes = hash.to_bytes_be();

        let (signature, recovery_id) = self.signing_key.sign_prehash_recoverable(&hash_bytes);

        let r_generic = signature.r().to_bytes();
        let s_generic = signature.s().to_bytes();
        let v = recovery_id.to_byte();

        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&r_generic);
        s_bytes.copy_from_slice(&s_generic);

        let (r_low, r_high) = bytes32_to_u256_pair(&r_bytes);
        let (s_low, s_high) = bytes32_to_u256_pair(&s_bytes);

        Ok([r_low, r_high, s_low, s_high, Felt::from(v as u64)])
    }
}

/// A secp256k1 public key coordinate as 32 big-endian bytes.
///
/// secp256k1 coordinates range up to ~2^256, beyond the Stark prime, so they
/// cannot be held in a single `Felt` without being reduced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EthCoordinate([u8; 32]);

impl EthCoordinate {
    /// The coordinate as 32 big-endian bytes.
    pub fn to_bytes_be(&self) -> [u8; 32] {
        self.0
    }

    /// The coordinate as a `(low, high)` u256 Felt pair for calldata.
    pub fn to_u256_pair(&self) -> (Felt, Felt) {
        bytes32_to_u256_pair(&self.0)
    }
}

impl PartialEq<Felt> for EthCoordinate {
    /// Equal only when the coordinate's exact value equals the felt.
    fn eq(&self, other: &Felt) -> bool {
        self.0 == other.to_bytes_be()
    }
}

/// Split a 32-byte big-endian value into `(low, high)` Felts for u256 encoding.
///
/// `high` = upper 16 bytes, `low` = lower 16 bytes.
fn bytes32_to_u256_pair(bytes: &[u8; 32]) -> (Felt, Felt) {
    let mut high_buf = [0u8; 16];
    let mut low_buf = [0u8; 16];
    high_buf.copy_from_slice(&bytes[..16]);
    low_buf.copy_from_slice(&bytes[16..]);

    let high = u128::from_be_bytes(high_buf);
    let low = u128::from_be_bytes(low_buf);

    (Felt::from(low), Felt::from(high))
}

/// Split a Felt (interpreted as a 32-byte big-endian value) into `(low, high)` Felt pair.
///
/// A `Felt` cannot hold a 256-bit secp256k1 coordinate, so this cannot encode
/// public key coordinates; use [`EthSigner::public_key_calldata`].
#[deprecated(
    since = "0.15.0",
    note = "a Felt cannot hold a 256-bit coordinate; use EthSigner::public_key_calldata"
)]
pub fn felt_to_u256_pair(felt: &Felt) -> (Felt, Felt) {
    let bytes = felt.to_bytes_be();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    bytes32_to_u256_pair(&arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A well-known test private key (DO NOT use in production).
    const TEST_KEY_HEX: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn test_from_private_key() {
        let bytes = hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let signer = EthSigner::from_private_key(&arr);
        assert!(signer.is_ok());
    }

    #[test]
    fn test_from_hex() {
        let signer = EthSigner::from_hex(TEST_KEY_HEX);
        assert!(signer.is_ok());
    }

    #[test]
    fn test_from_hex_no_prefix() {
        let signer =
            EthSigner::from_hex("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        assert!(signer.is_ok());
    }

    #[test]
    fn test_from_hex_invalid_length() {
        let result = EthSigner::from_hex("0xDEADBEEF");
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_uncompressed() {
        let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
        let pubkey = signer.public_key_uncompressed();
        // Uncompressed key starts with 0x04
        assert_eq!(pubkey[0], 0x04);
        assert_eq!(pubkey.len(), 65);
    }

    /// Known answers: the Hardhat development accounts 0 and 1, whose
    /// uncompressed public keys are published with the keys. Limbs were
    /// computed outside this crate (pure-integer secp256k1 scalar
    /// multiplication), so the test does not compare the code with itself.
    /// Regression test for audit finding H-1 (2026-11-04): coordinates were
    /// reduced modulo the Stark prime before being split.
    #[test]
    fn public_key_calldata_known_answers() {
        let cases = [
            (
                TEST_KEY_HEX,
                [
                    "0x87181b4fdfc625bd1a753fa7397fed75",
                    "0x8318535b54105d4a7aae60c08fc45f96",
                    "0xfac23e630c5d11f59f61fef57b0d2aa5",
                    "0x3547f11ca8696646f2f3acb08e31016a",
                ],
            ),
            (
                "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
                [
                    "0x0dc70cc661ca05e688601ad984f068b0",
                    "0xba5734d8f7091719471e7f7ed6b9df17",
                    "0xa521afd334e53807205fa2f08eec74f4",
                    "0xd67351e5f06073092499336ab0839ef8",
                ],
            ),
        ];
        for (key, expected) in cases {
            let signer = EthSigner::from_hex(key).unwrap();
            let expected = expected.map(|limb| Felt::from_hex(limb).unwrap());
            assert_eq!(signer.public_key_calldata(), expected, "{key}");
        }
    }

    #[test]
    fn public_key_calldata_splits_sec1_coordinates() {
        let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
        let sec1 = signer.public_key_uncompressed();
        let limb = |range: std::ops::Range<usize>| {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&sec1[range]);
            Felt::from(u128::from_be_bytes(buf))
        };
        assert_eq!(
            signer.public_key_calldata(),
            [limb(17..33), limb(1..17), limb(49..65), limb(33..49)]
        );
    }

    #[test]
    fn test_public_key_xy() {
        let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
        let (x, y) = signer.public_key_xy();
        // Both coordinates should be non-zero
        assert_ne!(x, Felt::ZERO);
        assert_ne!(y, Felt::ZERO);
    }

    #[test]
    fn test_public_key_xy_matches_uncompressed() {
        let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
        let (x, y) = signer.public_key_xy();
        let uncompressed = signer.public_key_uncompressed();

        assert_eq!(x.to_bytes_be()[..], uncompressed[1..33]);
        assert_eq!(y.to_bytes_be()[..], uncompressed[33..65]);
    }

    #[test]
    fn test_public_key_coordinates_round_trip_through_u256() {
        let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
        let (x, y) = signer.public_key_xy();
        let uncompressed = signer.public_key_uncompressed();

        for (coordinate, expected) in [(x, &uncompressed[1..33]), (y, &uncompressed[33..65])] {
            // This fixture exercises coordinates that the old Felt conversion reduced.
            let reduced = Felt::from_bytes_be_slice(expected);
            assert_ne!(coordinate.to_bytes_be(), reduced.to_bytes_be());
            assert_ne!(coordinate, reduced);

            let (low, high) = coordinate.to_u256_pair();
            let low_bytes = low.to_bytes_be();
            let high_bytes = high.to_bytes_be();
            assert_eq!(&low_bytes[..16], &[0u8; 16]);
            assert_eq!(&high_bytes[..16], &[0u8; 16]);
            assert_eq!(&low_bytes[16..], &expected[16..]);
            assert_eq!(&high_bytes[16..], &expected[..16]);

            let mut reconstructed = [0u8; 32];
            reconstructed[..16].copy_from_slice(&high_bytes[16..]);
            reconstructed[16..].copy_from_slice(&low_bytes[16..]);
            assert_eq!(reconstructed.as_slice(), expected);
        }
    }

    #[test]
    fn test_sign_hash() {
        let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
        let hash = Felt::from(0x1234567890ABCDEFu64);
        let sig = signer.sign_hash(&hash).unwrap();

        // Should return 5 Felts
        assert_eq!(sig.len(), 5);
        // r_low, r_high, s_low, s_high should be non-zero
        // (statistically impossible for both halves to be zero)
        assert!(sig[0] != Felt::ZERO || sig[1] != Felt::ZERO); // r
        assert!(sig[2] != Felt::ZERO || sig[3] != Felt::ZERO); // s
                                                               // v should be 0 or 1
        assert!(sig[4] == Felt::ZERO || sig[4] == Felt::ONE);
    }

    #[test]
    fn test_sign_hash_deterministic() {
        let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
        let hash = Felt::from(42u64);
        let sig1 = signer.sign_hash(&hash).unwrap();
        let sig2 = signer.sign_hash(&hash).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_u256_split_correctness() {
        // A known 32-byte value
        let mut bytes = [0u8; 32];
        // Set low bytes to 1
        bytes[31] = 1;
        let (low, high) = bytes32_to_u256_pair(&bytes);
        assert_eq!(low, Felt::ONE);
        assert_eq!(high, Felt::ZERO);

        // Set high bytes
        let mut bytes2 = [0u8; 32];
        bytes2[0] = 1; // highest byte
        let (low2, high2) = bytes32_to_u256_pair(&bytes2);
        assert_eq!(low2, Felt::ZERO);
        assert_ne!(high2, Felt::ZERO);
    }

    #[test]
    #[allow(deprecated)]
    fn test_felt_to_u256_pair() {
        let felt = Felt::from(0xDEADBEEFu64);
        let (low, high) = felt_to_u256_pair(&felt);
        assert_eq!(low, Felt::from(0xDEADBEEFu64));
        assert_eq!(high, Felt::ZERO);
    }

    #[test]
    fn test_different_keys_different_signatures() {
        let signer1 = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
        let signer2 = EthSigner::from_hex(
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        )
        .unwrap();

        let hash = Felt::from(42u64);
        let sig1 = signer1.sign_hash(&hash).unwrap();
        let sig2 = signer2.sign_hash(&hash).unwrap();

        // Different keys produce different signatures
        assert_ne!(sig1, sig2);
    }
}
