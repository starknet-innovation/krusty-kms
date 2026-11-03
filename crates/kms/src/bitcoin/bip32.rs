//! BIP-32 private-key derivation for the Bitcoin path, keeping every secret
//! intermediate in a fixed-size type that is wiped on drop.
//!
//! The shared `crate::derivation` helpers compute child keys with `BigUint`
//! and a `Vec`, whose heap copies are never wiped. Here the key is a `k256`
//! scalar inside `Zeroizing`, and the key bytes, chain code and HMAC output
//! live in `Zeroizing` arrays. Two copies stay outside this module's reach:
//! stack temporaries the compiler makes during scalar arithmetic, and the
//! HMAC-SHA512 state, which the `hmac` crate does not wipe without its
//! `zeroize` feature.

use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{NonZeroScalar, PublicKey, Scalar};
use krusty_kms_common::{KmsError, Result};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

const HARDENED: u32 = 0x8000_0000;

/// Derive the private key at `path` from a BIP-39 seed.
///
/// Like the shared helpers, an invalid child (`IL >= n` or a zero key) is an
/// error rather than a skip to the next index, since the path is fixed.
///
/// # Errors
///
/// `CryptoError` when the master key or a child key is invalid.
pub(super) fn derive_private_key(seed: &[u8], path: &[u32]) -> Result<Zeroizing<[u8; 32]>> {
    let mut output = hmac_sha512(b"Bitcoin seed", &[seed])?;
    let mut key = Zeroizing::new(parse_scalar(&output, "master key")?);
    let mut chain_code = Zeroizing::new([0u8; 32]);
    chain_code.copy_from_slice(&output[32..]);

    for &index in path {
        output = if index & HARDENED != 0 {
            let key_bytes = scalar_bytes(&key);
            hmac_sha512(&*chain_code, &[&[0x00], &*key_bytes, &index.to_be_bytes()])?
        } else {
            let public_key = compressed_public_key(&key)?;
            hmac_sha512(&*chain_code, &[&public_key, &index.to_be_bytes()])?
        };
        let tweak = Zeroizing::new(parse_scalar(&output, "child key")?);
        *key += *tweak;
        if bool::from(key.is_zero()) {
            return Err(KmsError::CryptoError(
                "BIP-32 child derivation failed: derived key is zero".into(),
            ));
        }
        chain_code.copy_from_slice(&output[32..]);
    }
    Ok(scalar_bytes(&key))
}

/// HMAC-SHA512 of `parts`, returned in a wiped buffer.
fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<[u8; 64]>> {
    let mut mac =
        HmacSha512::new_from_slice(key).map_err(|e| KmsError::CryptoError(e.to_string()))?;
    for part in parts {
        mac.update(part);
    }
    let mut tag = mac.finalize().into_bytes();
    let mut output = Zeroizing::new([0u8; 64]);
    output.copy_from_slice(&tag);
    tag.as_mut_slice().zeroize();
    Ok(output)
}

/// Parse the left half of an HMAC output as a non-zero scalar below `n`.
fn parse_scalar(output: &[u8; 64], what: &str) -> Result<Scalar> {
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&output[..32]);
    let scalar = Option::<Scalar>::from(Scalar::from_repr(repr.into()));
    repr.zeroize();
    match scalar {
        Some(scalar) if !bool::from(scalar.is_zero()) => Ok(scalar),
        _ => Err(KmsError::CryptoError(format!(
            "BIP-32 derivation failed: {what} is not below the curve order or is zero"
        ))),
    }
}

fn scalar_bytes(scalar: &Scalar) -> Zeroizing<[u8; 32]> {
    let mut repr = scalar.to_repr();
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&repr);
    repr.as_mut_slice().zeroize();
    bytes
}

fn compressed_public_key(scalar: &Scalar) -> Result<[u8; 33]> {
    let secret = Zeroizing::new(
        Option::<NonZeroScalar>::from(NonZeroScalar::new(*scalar))
            .ok_or_else(|| KmsError::CryptoError("BIP-32 key is zero".into()))?,
    );
    PublicKey::from_secret_scalar(&secret)
        .to_sec1_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| KmsError::CryptoError("compressed public key is not 33 bytes".into()))
}
