//! Deterministic Stark-curve ECDSA signing utilities, plus keyless verification.
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
//! - verification takes no secret; `Ok(false)` and `Err` both mean reject

use krusty_kms_common::{KmsError, SecretFelt};
use starknet_crypto::{get_public_key, rfc6979_generate_k, sign, verify, Felt, SignError};

/// Stark curve order n (order of the generator point).
///
/// Private keys must live in `[1, n)`. The field prime p is slightly larger
/// than n, so felt-parsable values in `[n, p)` are invalid keys that would
/// otherwise silently reduce mod n inside curve arithmetic.
const STARK_CURVE_ORDER_HEX: &str =
    "0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

/// Stark curve β parameter: `y² = x³ + x + β` (α is 1).
const STARK_BETA: Felt =
    Felt::from_hex_unchecked("0x6f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89");

/// Whether `x` could be a Stark public key, that is the x-coordinate of a
/// curve point.
///
/// A public key is an x-coordinate, and only about half the field's elements
/// are one: `y² = x³ + x + β` has a root for those and not for the rest. A
/// felt that is not one is no key's public key, whatever the private key, so
/// nothing derived from a seed can equal it. Zero is such a felt, since β is
/// not a square in this field.
pub fn is_stark_public_key(x: &Felt) -> bool {
    let y_squared = x * x * x + x + STARK_BETA;
    y_squared.sqrt().is_some()
}

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
        // `k` and a signature reveal the private key; wipe it on every path.
        let k = SecretFelt::new(rfc6979_generate_k(hash, private_key, seed.as_ref()));

        match sign(private_key, hash, k.expose_secret()) {
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

/// Verify a Stark ECDSA signature `(r, s)` over `hash` under `public_key`.
///
/// `public_key` is the signer's x-coordinate; either curve point with that x
/// is accepted, as on-chain. No secret is involved.
///
/// Returns `Ok(true)` only for a valid signature. `Ok(false)` means the
/// signature does not match the key and hash. `Err` means malformed input:
/// `hash` not below `2^251`, `r` or `s` zero or not below `2^251` (likewise
/// the inverse of `s` modulo the curve order), or `public_key` not an
/// x-coordinate on the curve. Both `Ok(false)` and `Err` mean **reject**.
///
/// Stark ECDSA is malleable: when `(r, s)` verifies, `(r, n - s)` does too if
/// it is in range. Do not use signature bytes as a unique identifier; count
/// co-signers by public key.
#[must_use = "Ok(false) and Err both mean reject"]
pub fn verify_stark_signature(
    public_key: &Felt,
    hash: &Felt,
    r: &Felt,
    s: &Felt,
) -> Result<bool, KmsError> {
    verify(public_key, hash, r, s)
        .map_err(|error| KmsError::CryptoError(format!("invalid stark signature input: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn verify_stark_signature_accepts_valid_and_rejects_everything_else() {
        let hash = Felt::from(0x1234u64);
        let signed = sign_stark_hash(&Felt::from(42u64), &hash).unwrap();
        let (pk, r, s) = (signed.public_key, signed.r, signed.s);
        let other_pk = stark_public_key(&Felt::from(43u64)).unwrap();
        let too_big = Felt::from_hex_unchecked(
            "0x800000000000000000000000000000000000000000000000000000000000000", // 2^251
        );

        assert!(verify_stark_signature(&pk, &hash, &r, &s).unwrap());

        // Mismatches: Ok(false).
        assert!(!verify_stark_signature(&pk, &(hash + Felt::ONE), &r, &s).unwrap());
        assert!(!verify_stark_signature(&pk, &hash, &(r + Felt::ONE), &s).unwrap());
        assert!(!verify_stark_signature(&pk, &hash, &r, &(s + Felt::ONE)).unwrap());
        assert!(!verify_stark_signature(&pk, &hash, &s, &r).unwrap());
        assert!(!verify_stark_signature(&other_pk, &hash, &r, &s).unwrap());

        // Malformed input: Err, never a panic.
        assert!(verify_stark_signature(&pk, &hash, &Felt::ZERO, &s).is_err());
        assert!(verify_stark_signature(&pk, &hash, &r, &Felt::ZERO).is_err());
        assert!(verify_stark_signature(&pk, &hash, &too_big, &s).is_err());
        assert!(verify_stark_signature(&pk, &hash, &r, &too_big).is_err());
        assert!(verify_stark_signature(&pk, &too_big, &r, &s).is_err());
        // Zero is not an x-coordinate on the curve (see `is_stark_public_key`).
        assert!(verify_stark_signature(&Felt::ZERO, &hash, &r, &s).is_err());
    }

    #[test]
    fn verify_stark_signature_accepts_an_external_vector() {
        // crypto-cpp vector, as carried by starknet-rust-crypto's own tests.
        let public_key = Felt::from_hex_unchecked(
            "0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
        );
        let r = Felt::from_hex_unchecked(
            "0x0411494b501a98abd8262b0da1351e17899a0c4ef23dd2f96fec5ba847310b20",
        );
        let s = Felt::from_hex_unchecked(
            "0x0405c3191ab3883ef2b763af35bc5f5d15b3b4e99461d70e84c654a351a7c81b",
        );

        assert!(verify_stark_signature(&public_key, &Felt::TWO, &r, &s).unwrap());
        assert!(!verify_stark_signature(&public_key, &Felt::THREE, &r, &s).unwrap());
    }

    #[test]
    fn verify_stark_signature_accepts_either_point_with_the_public_key_x() {
        // Keys d and n - d are the two points sharing one x-coordinate.
        let hash = Felt::from(0x1234u64);
        let key = Felt::from(42u64);
        let negated_key = Felt::from_hex(STARK_CURVE_ORDER_HEX).unwrap() - key;
        let public_key = stark_public_key(&key).unwrap();
        assert_eq!(public_key, stark_public_key(&negated_key).unwrap());

        for signer in [key, negated_key] {
            let signed = sign_stark_hash(&signer, &hash).unwrap();
            assert!(verify_stark_signature(&public_key, &hash, &signed.r, &signed.s).unwrap());
        }
    }

    #[test]
    fn verify_stark_signature_accepts_the_malleated_signature() {
        // Pins the documented malleability: callers must not key on (r, s).
        let hash = Felt::from(0x1234u64);
        let signed = sign_stark_hash(&Felt::from(42u64), &hash).unwrap();
        let order = Felt::from_hex(STARK_CURVE_ORDER_HEX).unwrap();
        let flipped = order - signed.s;

        assert!(verify_stark_signature(&signed.public_key, &hash, &signed.r, &flipped).unwrap());
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
