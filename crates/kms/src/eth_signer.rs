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
        let (x, y) = self.public_key_xy();
        let (x_low, x_high) = x.to_u256_pair();
        let (y_low, y_high) = y.to_u256_pair();
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

#[cfg(test)]
mod tests;
