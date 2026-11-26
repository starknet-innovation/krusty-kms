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
//! - verification takes no secret; only `Ok(())` means the signature is valid

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
///
/// A zero `hash` is signed, but [`verify_stark_signature`] rejects it.
///
/// The public key in the result is recomputed from `private_key` on every
/// call, which is one more variable-time multiplication by the private key.
/// Callers that already hold the public key should use
/// [`sign_stark_hash_with_public_key`].
pub fn sign_stark_hash(private_key: &Felt, hash: &Felt) -> Result<StarkSignature, KmsError> {
    validate_stark_private_key(private_key)?;
    let (r, s) = sign_with_validated_key(private_key, hash)?;
    // private_key validated above: get_public_key cannot hit the identity point
    let public_key = get_public_key(private_key);
    Ok(StarkSignature { public_key, r, s })
}

/// [`sign_stark_hash`] for a caller that already holds the signer's public key.
///
/// The public key is not recomputed from `private_key`. Instead the fresh
/// signature is verified under `public_key`, which involves no secret, and
/// the call fails if it does not verify. A returned signature is therefore
/// always valid for the returned `public_key`.
///
/// This catches a public key passed by mistake; it does not prove that
/// `public_key` belongs to `private_key`. Verification accepts either curve
/// point with a given x, so for each signature over a non-zero hash one other
/// x-coordinate, which anyone holding the signature can compute, also
/// verifies and is accepted here. Derive a public key you need to trust with
/// [`stark_public_key`].
///
/// `(r, s)` is identical to what [`sign_stark_hash`] returns for the same
/// private key and hash.
///
/// # Errors
///
/// As [`sign_stark_hash`], plus an error when the signature does not verify
/// under `public_key`. Roughly one signature in 2^55 has an `s` whose inverse
/// the verifier rejects as out of range; that surfaces as the same error for
/// a correct key pair.
pub fn sign_stark_hash_with_public_key(
    private_key: &Felt,
    public_key: &Felt,
    hash: &Felt,
) -> Result<StarkSignature, KmsError> {
    validate_stark_private_key(private_key)?;
    let (r, s) = sign_with_validated_key(private_key, hash)?;
    // The raw check, not `verify_stark_signature`: a zero hash is signed here
    // as in `sign_stark_hash`, and the signature under test is our own.
    if !matches!(verify(public_key, hash, &r, &s), Ok(true)) {
        return Err(KmsError::CryptoError(
            "stark signature does not verify under the supplied public key".to_string(),
        ));
    }
    Ok(StarkSignature {
        public_key: *public_key,
        r,
        s,
    })
}

/// Deterministic `(r, s)` over `hash`. `private_key` must already be validated.
fn sign_with_validated_key(private_key: &Felt, hash: &Felt) -> Result<(Felt, Felt), KmsError> {
    let mut seed = None;

    loop {
        // `k` and a signature reveal the private key; wipe it on every path.
        let k = SecretFelt::new(rfc6979_generate_k(hash, private_key, seed.as_ref()));

        match sign(private_key, hash, k.expose_secret()) {
            Ok(signature) => return Ok((signature.r, signature.s)),
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
/// Returns `Ok(())` only for a valid signature; every other outcome is an
/// `Err` and means **reject**: a signature that does not match the key and
/// hash, a zero `hash`, `hash` not below `2^251`, `r` or `s` zero or not below
/// `2^251` (likewise the inverse of `s` modulo the curve order), or a
/// `public_key` that is not an x-coordinate on the curve.
///
/// `public_key` is the signer's x-coordinate; either curve point with that x
/// is accepted, as on-chain. No secret is involved.
///
/// # The caller must compute `hash`
///
/// This verifies the given felt directly; nothing is hashed here. Recompute
/// `hash` from the data that was signed (for a transaction, from its fields)
/// and never take it from untrusted input such as a stored proposal. Anyone
/// can construct a `(hash, r, s)` triple that verifies under a given public
/// key when they are free to pick the hash. A zero hash is the simplest case
/// (for a public key below `2^251`, `r = s = public_key` satisfies the raw
/// check with no private key) and is rejected here; that guard does not
/// replace recomputing the hash.
///
/// # Malleability
///
/// When `(r, s)` verifies, `(r, n - s)` does too if it is in range. Do not use
/// signature bytes as a unique identifier; count co-signers by public key.
/// Because either point with the key's x is accepted, `(r, s)` also verifies
/// over `n - hash` if that is in range; that is harmless only because the
/// caller recomputes `hash`.
pub fn verify_stark_signature(
    public_key: &Felt,
    hash: &Felt,
    r: &Felt,
    s: &Felt,
) -> Result<(), KmsError> {
    if *hash == Felt::ZERO {
        return Err(KmsError::CryptoError(
            "stark signature hash must be non-zero".to_string(),
        ));
    }
    let valid = verify(public_key, hash, r, s).map_err(|error| {
        KmsError::CryptoError(format!("invalid stark signature input: {error}"))
    })?;
    if !valid {
        return Err(KmsError::CryptoError(
            "stark signature does not match the public key and hash".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
