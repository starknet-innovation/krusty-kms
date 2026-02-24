//! Secp256k1 (Ethereum) signer for Starknet account transactions.
//!
//! OZ Ethereum account contracts expect a 5-Felt signature:
//! `[r_low, r_high, s_low, s_high, v]` where `r` and `s` are the secp256k1
//! ECDSA signature components encoded as u256 pairs, and `v` is the recovery
//! parity (0 or 1).

use k256::ecdsa::{SigningKey, VerifyingKey};
use krusty_kms_common::{KmsError, Result};
use starknet_types_core::felt::Felt;
use zeroize::ZeroizeOnDrop;

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
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            return Err(KmsError::InvalidPrivateKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_private_key(&arr)
    }

    /// Get the uncompressed secp256k1 public key (65 bytes: `04 || x || y`).
    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        let verifying_key = VerifyingKey::from(&self.signing_key);
        let encoded = verifying_key.to_encoded_point(false);
        let bytes = encoded.as_bytes();
        let mut out = [0u8; 65];
        out.copy_from_slice(bytes);
        out
    }

    /// Get the public key as `(x, y)` coordinate Felts.
    ///
    /// These are used in the OZ Eth account constructor calldata.
    pub fn public_key_xy(&self) -> (Felt, Felt) {
        let uncompressed = self.public_key_uncompressed();
        // Skip the 0x04 prefix byte
        let x = Felt::from_bytes_be_slice(&uncompressed[1..33]);
        let y = Felt::from_bytes_be_slice(&uncompressed[33..65]);
        (x, y)
    }

    /// Sign a Starknet transaction hash, producing the 5-Felt signature
    /// `[r_low, r_high, s_low, s_high, v]` expected by OZ Eth accounts.
    ///
    /// The hash is interpreted as 32 big-endian bytes and signed directly
    /// with secp256k1 ECDSA (prehash mode).
    pub fn sign_hash(&self, hash: &Felt) -> Result<[Felt; 5]> {
        let hash_bytes = hash.to_bytes_be();

        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(&hash_bytes)
            .map_err(|e| KmsError::CryptoError(format!("secp256k1 signing failed: {e}")))?;

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
/// Used for encoding public key coordinates as u256 pairs in constructor calldata.
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
        let bytes = hex::decode(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
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
        let signer = EthSigner::from_hex(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        );
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

        let x_from_uncompressed = Felt::from_bytes_be_slice(&uncompressed[1..33]);
        let y_from_uncompressed = Felt::from_bytes_be_slice(&uncompressed[33..65]);

        assert_eq!(x, x_from_uncompressed);
        assert_eq!(y, y_from_uncompressed);
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
