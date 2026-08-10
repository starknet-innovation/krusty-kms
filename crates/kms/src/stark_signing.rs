//! Deterministic Stark-curve ECDSA signing utilities.
//!
//! Inputs:
//! - a Stark private key scalar
//! - a caller-supplied hash or felt message
//!
//! Outputs:
//! - Stark public key
//! - deterministic `(r, s)` signature values
//!
//! Invariants:
//! - signing is deterministic via RFC-6979 with cairo-compatible seed retry
//! - the helper signs the caller-supplied felt directly; it does not hash bytes
//! - out-of-range message values are rejected explicitly

use krusty_kms_common::KmsError;
use starknet_crypto::{get_public_key, rfc6979_generate_k, sign, Felt, SignError};

/// Stark curve order n (order of the generator point).
///
/// Private keys must live in `[1, n)`. The field prime p is slightly larger
/// than n, so felt-parsable values in `[n, p)` are invalid keys that would
/// otherwise silently reduce mod n inside curve arithmetic.
const STARK_CURVE_ORDER_HEX: &str =
    "0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

/// Deterministic Stark-curve signature output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkSignature {
    pub public_key: Felt,
    pub r: Felt,
    pub s: Felt,
}

/// Validate that `private_key` is a usable Stark private key: `1 <= key < n`.
///
/// `starknet_crypto::get_public_key` unwraps the identity point, so a zero
/// (or order-multiple) key panics without this guard.
pub fn validate_stark_private_key(private_key: &Felt) -> Result<(), KmsError> {
    let order = Felt::from_hex(STARK_CURVE_ORDER_HEX)
        .map_err(|e| KmsError::CryptoError(format!("invalid curve order constant: {e}")))?;
    if *private_key == Felt::ZERO || *private_key >= order {
        return Err(KmsError::CryptoError(
            "stark private key must be in [1, curve_order)".to_string(),
        ));
    }
    Ok(())
}

/// Derive the Stark public key corresponding to `private_key`.
///
/// Returns an error instead of panicking when `private_key` is zero or out of
/// the curve-order range (the upstream `get_public_key` unwraps the identity
/// point in that case).
pub fn stark_public_key(private_key: &Felt) -> Result<Felt, KmsError> {
    validate_stark_private_key(private_key)?;
    Ok(get_public_key(private_key))
}

/// Sign a caller-supplied felt using deterministic RFC-6979 Stark ECDSA.
pub fn sign_stark_hash(private_key: &Felt, hash: &Felt) -> Result<StarkSignature, KmsError> {
    validate_stark_private_key(private_key)?;
    let mut seed = None;

    loop {
        let k = rfc6979_generate_k(hash, private_key, seed.as_ref());

        match sign(private_key, hash, &k) {
            Ok(signature) => {
                return Ok(StarkSignature {
                    public_key: get_public_key(private_key),
                    r: signature.r,
                    s: signature.s,
                }); // private_key validated above: get_public_key cannot hit the identity point
            }
            Err(SignError::InvalidMessageHash) => {
                return Err(KmsError::CryptoError(
                    "stark signing message hash is out of range".to_string(),
                ));
            }
            Err(SignError::InvalidK) => {
                seed = Some(seed.unwrap_or(Felt::ZERO) + Felt::ONE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_crypto::verify;

    #[test]
    fn sign_stark_hash_is_deterministic() {
        let private_key = Felt::from(42u64);
        let hash = Felt::from(0x1234u64);

        let first = sign_stark_hash(&private_key, &hash).unwrap();
        let second = sign_stark_hash(&private_key, &hash).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn sign_stark_hash_produces_verifiable_signature() {
        let private_key = Felt::from(42u64);
        let hash = Felt::from(0x1234u64);

        let signed = sign_stark_hash(&private_key, &hash).unwrap();
        let verified = verify(&signed.public_key, &hash, &signed.r, &signed.s).unwrap();

        assert!(verified);
    }

    #[test]
    fn stark_public_key_matches_signature_output() {
        let private_key = Felt::from(42u64);
        let hash = Felt::from(0x1234u64);

        let public_key = stark_public_key(&private_key).unwrap();
        let signed = sign_stark_hash(&private_key, &hash).unwrap();

        assert_eq!(public_key, signed.public_key);
    }

    #[test]
    fn zero_private_key_is_rejected_without_panicking() {
        let zero = Felt::ZERO;
        let hash = Felt::from(0x1234u64);

        assert!(stark_public_key(&zero).is_err());
        assert!(sign_stark_hash(&zero, &hash).is_err());
    }

    #[test]
    fn curve_order_and_above_are_rejected_as_private_keys() {
        let order = Felt::from_hex(STARK_CURVE_ORDER_HEX).unwrap();
        let hash = Felt::from(0x1234u64);

        assert!(stark_public_key(&order).is_err());
        assert!(sign_stark_hash(&order, &hash).is_err());

        // A felt in [n, p) must not silently reduce mod n into a valid key.
        let above_order = order + Felt::ONE;
        assert!(stark_public_key(&above_order).is_err());
    }
}
