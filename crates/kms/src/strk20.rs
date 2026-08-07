//! STRK20 privacy-pool viewing-key derivation.
//!
//! The viewing key used by the Starknet Privacy SDK is derived deterministically
//! from a Stark private key and the active chain/pool scope, so it never has to
//! be persisted as a second secret. This mirrors the reference TypeScript
//! derivation exactly:
//!
//! ```text
//! message = starknet_keccak(chain_id + ":" + pool_address)
//! (r, s) = deterministic_stark_ecdsa(private_key, message)
//! reduced = Poseidon(r, s) mod n
//! vk = reduced < n / 2 ? reduced : n - reduced
//! ```
//!
//! where `n` is the Stark curve order. The `mod (n / 2) + 1` keeps `vk` inside
//! the SDK's valid viewing-key range `[1, n/2]`.
//!
//! Keeping this in `krusty-kms` means the viewing-key crypto lives in audited
//! Rust alongside the rest of the wallet's signing and hashing, rather than in
//! ad-hoc TypeScript.
//!
//! The two hashing stages either side of the signature are public
//! ([`strk20_viewing_key_message_hash`] and [`fold_strk20_viewing_key`]) so that
//! a signer which never reveals its private key — a hardware wallet — can supply
//! the middle step itself and still land on a key this module would recognize.
//! [`derive_strk20_viewing_key`] is exactly their composition, and a test pins
//! that, so the two paths cannot drift apart.

use crate::stark_signing::sign_stark_hash;
use krusty_kms_common::{KmsError, Result};
use krusty_kms_crypto::poseidon_hash_many;
use num_bigint::BigUint;
use num_traits::Num;
use sha3::{Digest, Keccak256};
use starknet_types_core::felt::Felt;

/// Stark curve order `n` in hex. Viewing keys live in the range `[1, n/2]`.
const CURVE_ORDER_HEX: &str = "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

/// `starknet_keccak`: Keccak-256 truncated to 250 bits (top 6 bits cleared).
///
/// Matches the `starknetKeccak` WASM binding and starknet.js.
fn starknet_keccak(data: &[u8]) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut bytes: [u8; 32] = hasher.finalize().into();
    // Mask the top 6 bits so the result fits the 250-bit Stark field.
    bytes[0] &= 0x03;
    Felt::from_bytes_be_slice(&bytes)
}

/// Stark curve order `n` as a `BigUint`.
fn curve_order() -> BigUint {
    BigUint::from_str_radix(CURVE_ORDER_HEX, 16).expect("CURVE_ORDER_HEX is a valid hex constant")
}

/// Canonicalize one scope component, rejecting zero and non-shortest-form hex.
///
/// The scope is part of the signed message, so accepting two spellings of the
/// same value would derive two different keys for one pool.
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

/// The message whose signature a viewing key is derived from:
/// `starknet_keccak("<chain_id>:<pool_address>")`.
///
/// Exposed as its own stage so a signer that cannot reveal its private key — a
/// hardware wallet — can sign exactly the message this module would have signed
/// itself. Scope canonicalization lives here rather than at the call site
/// precisely so callers cannot drift on it: a different message yields a
/// different key, and a viewing key registered with the pool cannot be changed.
pub fn strk20_viewing_key_message_hash(chain_id: &str, pool_address: &str) -> Result<Felt> {
    let chain_id = canonical_scope(chain_id, "chain id")?;
    let pool_address = canonical_scope(pool_address, "pool address")?;
    Ok(starknet_keccak(
        format!("{chain_id}:{pool_address}").as_bytes(),
    ))
}

/// Fold an ECDSA signature over [`strk20_viewing_key_message_hash`] into a
/// viewing key.
///
/// Laws:
/// - **Range:** the result is always in `[1, n/2]`, the range the pool's
///   `is_canonical_key` accepts. Total — every `(r, s)` pair folds.
/// - **Determinism:** the same pair always folds to the same key.
/// - **Provenance independence:** the fold sees only `(r, s)`, so a signature
///   produced on a hardware device folds exactly as a host-produced one does.
///
/// Note the argument order is load-bearing: the pair is Poseidon-hashed in
/// order, so swapping `r` and `s` silently yields a different valid-looking key.
///
/// Signature validity is the caller's concern. A meaningless pair (zeroes, say)
/// folds to a well-formed key rather than an error, because a real signer cannot
/// produce one and the callers that accept device output already validate it at
/// their trust boundary.
pub fn fold_strk20_viewing_key(r: &Felt, s: &Felt) -> Felt {
    let material = poseidon_hash_many(&[*r, *s]);
    let order = curve_order();
    let max_viewing_key = &order >> 1;
    let reduced = BigUint::from_bytes_be(&material.to_bytes_be()) % &order;
    let canonical = if reduced < max_viewing_key {
        reduced
    } else {
        &order - reduced
    };
    let viewing_key = if canonical == BigUint::from(0u8) {
        BigUint::from(1u8)
    } else {
        canonical
    };
    Felt::from_bytes_be_slice(&viewing_key.to_bytes_be())
}

/// Derive the STRK20 viewing key from a Stark `private_key` and chain/pool scope.
///
/// The composition of the two stages above; the returned felt is guaranteed to
/// be in `[1, n/2]`.
pub fn derive_strk20_viewing_key(
    private_key: &Felt,
    chain_id: &str,
    pool_address: &str,
) -> Result<Felt> {
    let message_hash = strk20_viewing_key_message_hash(chain_id, pool_address)?;
    let signature = sign_stark_hash(private_key, &message_hash)?;
    Ok(fold_strk20_viewing_key(&signature.r, &signature.s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vk_hex(private_key: &str, chain_id: &str, pool_address: &str) -> String {
        let pk = Felt::from_hex(private_key).expect("valid private key hex");
        format!(
            "{:#x}",
            derive_strk20_viewing_key(&pk, chain_id, pool_address).expect("derivation succeeds")
        )
    }

    /// Known-answer vectors generated independently from the pinned privacy
    /// SDK demo's `deriveViewingKey` with `starknet@10.0.2`.
    #[test]
    fn viewing_key_known_answers() {
        assert_eq!(
            vk_hex("0x1", "0x534e5f5345504f4c4941", "0x123"),
            "0x27cae3ff78010cbec0f29c0c94420cc4d41ca326d664e510cca4dcc6082beb3",
        );
        assert_eq!(
            vk_hex("0x1", "0x534e5f4d41494e", "0x123"),
            "0x12e78a27fea179a0887b09dd9066d162240362c87756141473ecac377306338",
        );
        assert_eq!(
            vk_hex("0xdeadbeef", "0x534e5f5345504f4c4941", "0x456"),
            "0x2d4dfb02335842c25e68b48e7b9c234aa40d17c90fe1d597bd47ccdc6388853",
        );
    }

    #[test]
    fn viewing_key_is_deterministic_and_in_range() {
        let pk = Felt::from_hex("0xabc").unwrap();
        let a = derive_strk20_viewing_key(&pk, "0x1", "0x2").unwrap();
        let b = derive_strk20_viewing_key(&pk, "0x1", "0x2").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, Felt::ZERO);

        let max_viewing_key = curve_order() >> 1;
        let a_uint = BigUint::from_bytes_be(&a.to_bytes_be());
        assert!(a_uint >= BigUint::from(1u8));
        assert!(a_uint <= max_viewing_key);
    }

    #[test]
    fn viewing_key_changes_across_chain_and_pool_scopes() {
        let pk = Felt::from_hex("0xabc").unwrap();
        let first = derive_strk20_viewing_key(&pk, "0x1", "0x2").unwrap();
        let other_chain = derive_strk20_viewing_key(&pk, "0x3", "0x2").unwrap();
        let other_pool = derive_strk20_viewing_key(&pk, "0x1", "0x4").unwrap();

        assert_ne!(first, other_chain);
        assert_ne!(first, other_pool);
    }

    #[test]
    fn viewing_key_rejects_missing_scope() {
        let pk = Felt::from_hex("0xabc").unwrap();
        assert!(derive_strk20_viewing_key(&pk, "", "0x2").is_err());
        assert!(derive_strk20_viewing_key(&pk, "0x1", "").is_err());
    }

    /// The composition law: the one-shot derivation is exactly its two stages.
    /// This is what lets a hardware signer substitute its own signature for the
    /// middle step and arrive at the same key.
    #[test]
    fn viewing_key_is_the_composition_of_its_stages() {
        let pk = Felt::from_hex("0xabc").unwrap();
        let chain_id = "0x534e5f5345504f4c4941";
        let pool_address = "0x123";

        let message_hash = strk20_viewing_key_message_hash(chain_id, pool_address).unwrap();
        let signature = sign_stark_hash(&pk, &message_hash).unwrap();
        let staged = fold_strk20_viewing_key(&signature.r, &signature.s);

        assert_eq!(
            derive_strk20_viewing_key(&pk, chain_id, pool_address).unwrap(),
            staged,
        );
    }

    /// Range law: every real signature folds into the pool's accepted
    /// `[1, n/2]`, whatever the key or message.
    #[test]
    fn fold_lands_in_the_canonical_range() {
        let max_viewing_key = curve_order() >> 1;

        for key in ["0x1", "0xabc", "0xdeadbeef"] {
            let pk = Felt::from_hex(key).unwrap();
            for message in ["0x1", "0x2222", "0x7fff"] {
                let hash = Felt::from_hex(message).unwrap();
                let signature = sign_stark_hash(&pk, &hash).unwrap();
                let folded = fold_strk20_viewing_key(&signature.r, &signature.s);
                let value = BigUint::from_bytes_be(&folded.to_bytes_be());

                assert!(value >= BigUint::from(1u8));
                assert!(value <= max_viewing_key);
            }
        }
    }

    /// The pair is hashed in order, so a caller that swaps `r` and `s` gets a
    /// different key that still looks valid. Pinned so the argument order can
    /// never be "cleaned up" silently — the failure mode is an unrecoverable
    /// registration, not a test failure in production.
    #[test]
    fn fold_is_order_sensitive() {
        let r = Felt::from_hex("0x1").unwrap();
        let s = Felt::from_hex("0x2").unwrap();

        assert_ne!(
            fold_strk20_viewing_key(&r, &s),
            fold_strk20_viewing_key(&s, &r),
        );
    }

    #[test]
    fn message_hash_is_deterministic_and_scoped() {
        let first = strk20_viewing_key_message_hash("0x1", "0x2").unwrap();

        assert_eq!(
            first,
            strk20_viewing_key_message_hash("0x1", "0x2").unwrap()
        );
        assert_ne!(
            first,
            strk20_viewing_key_message_hash("0x3", "0x2").unwrap()
        );
        assert_ne!(
            first,
            strk20_viewing_key_message_hash("0x1", "0x4").unwrap()
        );
    }

    /// The scope rules belong to the message-hash stage now, so they must reject
    /// there too — a caller reaching the stage directly gets the same guarantees
    /// the one-shot derivation has.
    #[test]
    fn message_hash_rejects_missing_and_noncanonical_scope() {
        assert!(strk20_viewing_key_message_hash("", "0x2").is_err());
        assert!(strk20_viewing_key_message_hash("0x1", "").is_err());
        assert!(strk20_viewing_key_message_hash("0x01", "0x2").is_err());
        assert!(strk20_viewing_key_message_hash("0x1", "0x02").is_err());
        assert!(strk20_viewing_key_message_hash("not-hex", "0x2").is_err());
        assert!(strk20_viewing_key_message_hash("0x1", "0x0").is_err());
    }

    #[test]
    fn viewing_key_rejects_noncanonical_scope() {
        let pk = Felt::from_hex("0xabc").unwrap();
        assert!(derive_strk20_viewing_key(&pk, "0x01", "0x2").is_err());
        assert!(derive_strk20_viewing_key(&pk, "0x1", "0x02").is_err());
        assert!(derive_strk20_viewing_key(&pk, "not-hex", "0x2").is_err());
        assert!(derive_strk20_viewing_key(&pk, "0x1", "0x0").is_err());
    }
}
