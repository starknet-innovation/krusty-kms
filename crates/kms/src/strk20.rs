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

/// Derive the STRK20 viewing key from a Stark `private_key` and chain/pool scope.
///
/// The returned felt is guaranteed to be in `[1, n/2]`.
pub fn derive_strk20_viewing_key(
    private_key: &Felt,
    chain_id: &str,
    pool_address: &str,
) -> Result<Felt> {
    let canonical_scope = |value: &str, label: &str| -> Result<String> {
        let felt = Felt::from_hex(value)
            .map_err(|_| KmsError::CryptoError(format!("STRK20 {label} must be canonical hex")))?;
        let canonical = format!("{felt:#x}");
        if felt == Felt::ZERO || value != canonical {
            return Err(KmsError::CryptoError(format!(
                "STRK20 {label} must be canonical non-zero hex"
            )));
        }
        Ok(canonical)
    };
    let chain_id = canonical_scope(chain_id, "chain id")?;
    let pool_address = canonical_scope(pool_address, "pool address")?;
    let message = format!("{chain_id}:{pool_address}");
    let message_hash = starknet_keccak(message.as_bytes());
    let signature = sign_stark_hash(private_key, &message_hash)?;
    let material = poseidon_hash_many(&[signature.r, signature.s]);
    let order = BigUint::from_str_radix(CURVE_ORDER_HEX, 16)
        .expect("CURVE_ORDER_HEX is a valid hex constant");
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
    Ok(Felt::from_bytes_be_slice(&viewing_key.to_bytes_be()))
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

        let max_viewing_key = BigUint::from_str_radix(CURVE_ORDER_HEX, 16).unwrap() >> 1;
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

    #[test]
    fn viewing_key_rejects_noncanonical_scope() {
        let pk = Felt::from_hex("0xabc").unwrap();
        assert!(derive_strk20_viewing_key(&pk, "0x01", "0x2").is_err());
        assert!(derive_strk20_viewing_key(&pk, "0x1", "0x02").is_err());
        assert!(derive_strk20_viewing_key(&pk, "not-hex", "0x2").is_err());
        assert!(derive_strk20_viewing_key(&pk, "0x1", "0x0").is_err());
    }
}
