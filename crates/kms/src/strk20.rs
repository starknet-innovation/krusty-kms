//! STRK20 privacy-pool viewing-key derivation.
//!
//! [`derive_strk20_viewing_key`] preserves the original domain-separated
//! derivation. New integrations should use
//! [`derive_scoped_strk20_secret_viewing_key`], which binds the key to a chain
//! and pool and can be split around a hardware signer with
//! [`strk20_viewing_key_message_hash`] and
//! [`fold_strk20_secret_viewing_key`].
//!
//! # Memory and timing
//!
//! A viewing key, and the hash it is reduced from, are secret. The reduction
//! and fold themselves run on fixed-size `crypto-bigint` integers held in
//! `Zeroizing`, with no branch or early exit on their value.
//!
//! Not covered: the hash result before it is wrapped, temporaries inside
//! `crypto-bigint`, and copies the compiler makes when it moves a value. Not
//! constant-time: the hashes and signature checks before the fold, and the
//! conversions between `Felt` and bytes on the way in and out (lambdaworks).
//! [`derive_strk20_viewing_key`], [`fold_strk20_viewing_key`] and
//! [`derive_scoped_strk20_viewing_key`] return a `Copy` `Felt` that cannot be
//! wiped from the return slot; the unscoped derivation has no secret variant.

use crate::stark_signing::sign_stark_hash;
use crypto_bigint::{CtLt, CtSelect, NonZero, U256};
use krusty_kms_common::{KmsError, Result, SecretFelt};
use krusty_kms_crypto::poseidon_hash_many;
use sha3::{Digest, Keccak256};
use starknet_crypto::verify;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};
use zeroize::Zeroizing;

/// Domain separator used by the original unscoped viewing-key derivation.
pub const STRK20_VIEWING_KEY_DOMAIN: &str = "pharaoh.strk20.viewing_key.v1";

/// Stark curve order `n`.
const CURVE_ORDER: NonZero<U256> = NonZero::<U256>::new_unwrap(U256::from_be_hex(
    "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f",
));

/// `floor(n / 2)`, the exclusive upper bound of a scoped viewing key.
const HALF_ORDER: NonZero<U256> = NonZero::<U256>::new_unwrap(CURVE_ORDER.as_ref().shr_vartime(1));

/// Read a secret felt as a fixed-size integer, wiping the byte copy.
fn secret_uint(felt: &Felt) -> Zeroizing<U256> {
    let bytes = Zeroizing::new(felt.to_bytes_be());
    Zeroizing::new(U256::from_be_slice(bytes.as_ref()))
}

/// Wrap a secret integer below the field prime as a [`SecretFelt`].
fn secret_felt(value: &U256) -> SecretFelt {
    let encoded = Zeroizing::new(value.to_be_bytes());
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(encoded.as_ref());
    SecretFelt::new(Felt::from_bytes_be(&bytes))
}

/// Reduce a secret hash, which may be anywhere below the field prime, mod `n`.
fn reduce_mod_order(material: &Felt) -> Zeroizing<U256> {
    Zeroizing::new(secret_uint(material).rem(&CURVE_ORDER))
}

/// `starknet_keccak`: Keccak-256 truncated to 250 bits (top 6 bits cleared).
fn starknet_keccak(data: &[u8]) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut bytes: [u8; 32] = hasher.finalize().into();
    bytes[0] &= 0x03;
    Felt::from_bytes_be_slice(&bytes)
}

/// Derive the original, unscoped STRK20 viewing key from a Stark private key.
///
/// Retained for API compatibility. New integrations should use
/// [`derive_scoped_strk20_secret_viewing_key`] so the result cannot be reused
/// across chains or pools.
pub fn derive_strk20_viewing_key(private_key: &Felt) -> Felt {
    let domain = starknet_keccak(STRK20_VIEWING_KEY_DOMAIN.as_bytes());
    let material = SecretFelt::new(Pedersen::hash(&domain, private_key));
    let reduced = Zeroizing::new(secret_uint(material.expose_secret()).rem(&HALF_ORDER));
    // `reduced < floor(n / 2)`, so adding one cannot wrap.
    let viewing_key = Zeroizing::new(reduced.wrapping_add(&U256::ONE));
    *secret_felt(&viewing_key).expose_secret()
}

fn canonical_scope(value: &str, label: &str) -> Result<String> {
    let felt = Felt::from_hex(value)
        .map_err(|_| KmsError::CryptoError(format!("STRK20 {label} must be canonical hex")))?;
    let canonical = format!("{felt:#x}");
    if felt == Felt::ZERO || value != canonical {
        return Err(KmsError::CryptoError(format!(
            "STRK20 {label} must be canonical non-zero hex"
        )));
    }
    Ok(canonical)
}

/// Return the hash a hardware signer must sign for a chain- and pool-scoped key.
///
/// The message is `starknet_keccak("<chain_id>:<pool_address>")`. Both scope
/// values must be shortest-form, lowercase, non-zero `0x`-prefixed felts.
pub fn strk20_viewing_key_message_hash(chain_id: &str, pool_address: &str) -> Result<Felt> {
    let chain_id = canonical_scope(chain_id, "chain id")?;
    let pool_address = canonical_scope(pool_address, "pool address")?;
    Ok(starknet_keccak(
        format!("{chain_id}:{pool_address}").as_bytes(),
    ))
}

/// Verify and fold a Stark ECDSA signature into a scoped STRK20 viewing key.
///
/// `public_key` is the expected signer's Stark public-key x-coordinate. The
/// signature must verify over `message_hash`; malformed, swapped, wrong-key, and
/// wrong-message signatures fail closed. The result is always in
/// `[1, floor(n / 2))`, the strict range enforced by the privacy-pool contract.
/// The key is returned in a [`SecretFelt`], which wipes itself on drop.
pub fn fold_strk20_secret_viewing_key(
    public_key: &Felt,
    message_hash: &Felt,
    r: &Felt,
    s: &Felt,
) -> Result<SecretFelt> {
    let valid = verify(public_key, message_hash, r, s)
        .map_err(|error| KmsError::CryptoError(format!("invalid STRK20 signature: {error}")))?;
    if !valid {
        return Err(KmsError::CryptoError(
            "STRK20 signature does not match the public key and message".to_string(),
        ));
    }

    let material = SecretFelt::new(poseidon_hash_many(&[*r, *s]));
    let reduced = reduce_mod_order(material.expose_secret());
    Ok(secret_felt(&fold_lower_half(&reduced)))
}

/// [`fold_strk20_secret_viewing_key`] returning a plain `Felt`.
///
/// `Felt` is `Copy`, so the key cannot be wiped from the return slot. Prefer
/// [`fold_strk20_secret_viewing_key`].
pub fn fold_strk20_viewing_key(
    public_key: &Felt,
    message_hash: &Felt,
    r: &Felt,
    s: &Felt,
) -> Result<Felt> {
    fold_strk20_secret_viewing_key(public_key, message_hash, r, s).map(|key| *key.expose_secret())
}

/// Fold a scalar below `n` into the contract's strict `[1, floor(n / 2))` range.
///
/// Both candidates are always computed and the result is selected by mask, so
/// neither the control flow nor the memory access pattern depends on `reduced`
/// (in release builds; the debug assertion below compares it in variable time).
fn fold_lower_half(reduced: &U256) -> Zeroizing<U256> {
    debug_assert!(reduced < CURVE_ORDER.as_ref());
    let negated = Zeroizing::new(CURVE_ORDER.as_ref().wrapping_sub(reduced));
    let folded = Zeroizing::new(U256::ct_select(
        &negated,
        reduced,
        reduced.ct_lt(HALF_ORDER.as_ref()),
    ));

    // For odd n, floor(n/2) and ceil(n/2) negate to each other; neither is
    // strictly below floor(n/2). Match the privacy client and map both to 1.
    // `reduced = 0` stays 0, which is out of range as well.
    let in_range = folded.is_nonzero() & folded.ct_lt(HALF_ORDER.as_ref());
    Zeroizing::new(U256::ct_select(&U256::ONE, &folded, in_range))
}

/// Derive a chain- and pool-scoped STRK20 viewing key from a Stark private key.
///
/// The private key must be in `[1, n)`. Invalid keys and scopes return an error;
/// the result is always in `[1, floor(n / 2))`. The key is returned in a
/// [`SecretFelt`], which wipes itself on drop.
pub fn derive_scoped_strk20_secret_viewing_key(
    private_key: &Felt,
    chain_id: &str,
    pool_address: &str,
) -> Result<SecretFelt> {
    let message_hash = strk20_viewing_key_message_hash(chain_id, pool_address)?;
    let signature = sign_stark_hash(private_key, &message_hash)?;
    fold_strk20_secret_viewing_key(
        &signature.public_key,
        &message_hash,
        &signature.r,
        &signature.s,
    )
}

/// [`derive_scoped_strk20_secret_viewing_key`] returning a plain `Felt`.
///
/// `Felt` is `Copy`, so the key cannot be wiped from the return slot. Prefer
/// [`derive_scoped_strk20_secret_viewing_key`].
pub fn derive_scoped_strk20_viewing_key(
    private_key: &Felt,
    chain_id: &str,
    pool_address: &str,
) -> Result<Felt> {
    derive_scoped_strk20_secret_viewing_key(private_key, chain_id, pool_address)
        .map(|key| *key.expose_secret())
}

#[cfg(test)]
mod tests;
