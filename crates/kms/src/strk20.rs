//! STRK20 privacy-pool viewing-key derivation.
//!
//! [`derive_strk20_viewing_key`] preserves the original domain-separated
//! derivation. New integrations should use [`derive_scoped_strk20_viewing_key`],
//! which binds the key to a chain and pool and can be split around a hardware
//! signer with [`strk20_viewing_key_message_hash`] and
//! [`fold_strk20_viewing_key`].

use crate::stark_signing::sign_stark_hash;
use krusty_kms_common::{KmsError, Result};
use krusty_kms_crypto::poseidon_hash_many;
use num_bigint::BigUint;
use num_traits::Num;
use sha3::{Digest, Keccak256};
use starknet_crypto::verify;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};

/// Domain separator used by the original unscoped viewing-key derivation.
pub const STRK20_VIEWING_KEY_DOMAIN: &str = "pharaoh.strk20.viewing_key.v1";

/// Stark curve order `n` in hex.
const CURVE_ORDER_HEX: &str = "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

/// `starknet_keccak`: Keccak-256 truncated to 250 bits (top 6 bits cleared).
fn starknet_keccak(data: &[u8]) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut bytes: [u8; 32] = hasher.finalize().into();
    bytes[0] &= 0x03;
    Felt::from_bytes_be_slice(&bytes)
}

fn curve_order() -> BigUint {
    BigUint::from_str_radix(CURVE_ORDER_HEX, 16).expect("curve order is valid hex")
}

/// Derive the original, unscoped STRK20 viewing key from a Stark private key.
///
/// Retained for API compatibility. New integrations should use
/// [`derive_scoped_strk20_viewing_key`] so the result cannot be reused across
/// chains or pools.
pub fn derive_strk20_viewing_key(private_key: &Felt) -> Felt {
    let domain = starknet_keccak(STRK20_VIEWING_KEY_DOMAIN.as_bytes());
    let material = Pedersen::hash(&domain, private_key);
    let max_viewing_key = curve_order() >> 1;
    let material = BigUint::from_bytes_be(&material.to_bytes_be());
    let viewing_key: BigUint = (material % &max_viewing_key) + BigUint::from(1u8);
    Felt::from_bytes_be_slice(&viewing_key.to_bytes_be())
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
pub fn fold_strk20_viewing_key(
    public_key: &Felt,
    message_hash: &Felt,
    r: &Felt,
    s: &Felt,
) -> Result<Felt> {
    let valid = verify(public_key, message_hash, r, s)
        .map_err(|error| KmsError::CryptoError(format!("invalid STRK20 signature: {error}")))?;
    if !valid {
        return Err(KmsError::CryptoError(
            "STRK20 signature does not match the public key and message".to_string(),
        ));
    }

    let order = curve_order();
    let material = poseidon_hash_many(&[*r, *s]);
    let reduced = BigUint::from_bytes_be(&material.to_bytes_be()) % &order;
    Ok(Felt::from_bytes_be_slice(
        &fold_lower_half(reduced, &order).to_bytes_be(),
    ))
}

/// Fold a reduced scalar into the contract's strict `[1, floor(n / 2))` range.
fn fold_lower_half(reduced: BigUint, order: &BigUint) -> BigUint {
    debug_assert!(&reduced < order);
    let half_order = order >> 1;
    let folded = if reduced < half_order {
        reduced
    } else {
        order - reduced
    };

    // For odd n, floor(n/2) and ceil(n/2) negate to each other; neither is
    // strictly below floor(n/2). Match the privacy client and map both to 1.
    if folded == BigUint::from(0u8) || folded >= half_order {
        BigUint::from(1u8)
    } else {
        folded
    }
}

/// Derive a chain- and pool-scoped STRK20 viewing key from a Stark private key.
///
/// The private key must be in `[1, n)`. Invalid keys and scopes return an error;
/// the result is always in `[1, floor(n / 2))`.
pub fn derive_scoped_strk20_viewing_key(
    private_key: &Felt,
    chain_id: &str,
    pool_address: &str,
) -> Result<Felt> {
    let message_hash = strk20_viewing_key_message_hash(chain_id, pool_address)?;
    let signature = sign_stark_hash(private_key, &message_hash)?;
    fold_strk20_viewing_key(
        &signature.public_key,
        &message_hash,
        &signature.r,
        &signature.s,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vk_hex(private_key: &str) -> String {
        let pk = Felt::from_hex(private_key).expect("valid private key hex");
        format!("{:#x}", derive_strk20_viewing_key(&pk))
    }

    /// Domain keccak anchored to starknet.js `hash.starknetKeccak(DOMAIN)`.
    #[test]
    fn domain_keccak_matches_starknet_js() {
        assert_eq!(
            format!(
                "{:#x}",
                starknet_keccak(STRK20_VIEWING_KEY_DOMAIN.as_bytes())
            ),
            "0x2da93d6437c3a6366d206b66d62846f06a35c1751250d74d4fd1b2c68838d41",
        );
    }

    /// Known-answer vectors generated independently with `starknet@10.0.2`:
    /// `Pedersen(starknetKeccak(DOMAIN), pk) % (CURVE.n / 2) + 1`.
    #[test]
    fn viewing_key_known_answers() {
        assert_eq!(
            vk_hex("0x1"),
            "0x18c6e892dbe125696102d8c69a3adc9ca0c73d92bcb35fa166c2cb92914ba05",
        );
        assert_eq!(
            vk_hex("0x2"),
            "0xb3914270984ae1ddc5bb5586f9558cf26666a63096fd18fbbaff342ffdba01",
        );
        assert_eq!(
            vk_hex("0xdeadbeef"),
            "0xb8055c8793acf944ec7d69de834ebd88db9f5a7e19f0ecbbc6c17cb0ffbb66",
        );
        assert_eq!(
            vk_hex("0x07a1f2c3b4a5968778695a4b3c2d1e0f00112233445566778899aabbccddeeff"),
            "0x206f4f73f030abbaf454d1a66376ce1fe63e6938df1669753b84f30777e6116",
        );
    }

    #[test]
    fn viewing_key_is_deterministic_and_in_range() {
        let pk = Felt::from_hex("0xabc").unwrap();
        let a = derive_strk20_viewing_key(&pk);
        let b = derive_strk20_viewing_key(&pk);
        assert_eq!(a, b);
        assert_ne!(a, Felt::ZERO);

        let max_viewing_key = BigUint::from_str_radix(CURVE_ORDER_HEX, 16).unwrap() >> 1;
        let a_uint = BigUint::from_bytes_be(&a.to_bytes_be());
        assert!(a_uint >= BigUint::from(1u8));
        assert!(a_uint <= max_viewing_key);
    }

    fn scoped_hex(private_key: &str, chain_id: &str, pool_address: &str) -> String {
        let private_key = Felt::from_hex(private_key).unwrap();
        format!(
            "{:#x}",
            derive_scoped_strk20_viewing_key(&private_key, chain_id, pool_address).unwrap()
        )
    }

    #[test]
    fn scoped_known_answers_match_the_privacy_demo() {
        assert_eq!(
            scoped_hex("0x1", "0x534e5f5345504f4c4941", "0x123"),
            "0x27cae3ff78010cbec0f29c0c94420cc4d41ca326d664e510cca4dcc6082beb3",
        );
        assert_eq!(
            scoped_hex("0x1", "0x534e5f4d41494e", "0x123"),
            "0x12e78a27fea179a0887b09dd9066d162240362c87756141473ecac377306338",
        );
        assert_eq!(
            scoped_hex("0xdeadbeef", "0x534e5f5345504f4c4941", "0x456"),
            "0x2d4dfb02335842c25e68b48e7b9c234aa40d17c90fe1d597bd47ccdc6388853",
        );
    }

    #[test]
    fn scoped_derivation_is_the_verified_composition() {
        let private_key = Felt::from_hex("0xabc").unwrap();
        let message_hash = strk20_viewing_key_message_hash("0x1", "0x2").unwrap();
        let signature = sign_stark_hash(&private_key, &message_hash).unwrap();
        let staged = fold_strk20_viewing_key(
            &signature.public_key,
            &message_hash,
            &signature.r,
            &signature.s,
        )
        .unwrap();

        assert_eq!(
            derive_scoped_strk20_viewing_key(&private_key, "0x1", "0x2").unwrap(),
            staged,
        );
    }

    #[test]
    fn fold_rejects_unverified_signature_material() {
        let private_key = Felt::from_hex("0xabc").unwrap();
        let message_hash = strk20_viewing_key_message_hash("0x1", "0x2").unwrap();
        let signature = sign_stark_hash(&private_key, &message_hash).unwrap();
        let other_public_key = crate::stark_signing::stark_public_key(&Felt::ONE).unwrap();

        assert!(fold_strk20_viewing_key(
            &other_public_key,
            &message_hash,
            &signature.r,
            &signature.s,
        )
        .is_err());
        assert!(fold_strk20_viewing_key(
            &signature.public_key,
            &(message_hash + Felt::ONE),
            &signature.r,
            &signature.s,
        )
        .is_err());
        assert!(fold_strk20_viewing_key(
            &signature.public_key,
            &message_hash,
            &signature.s,
            &signature.r,
        )
        .is_err());
        assert!(fold_strk20_viewing_key(
            &signature.public_key,
            &message_hash,
            &Felt::ZERO,
            &signature.s,
        )
        .is_err());
    }

    #[test]
    fn fold_is_strictly_below_half_order() {
        let order = curve_order();
        let half_order: BigUint = &order >> 1;

        assert_eq!(
            fold_lower_half(BigUint::from(0u8), &order),
            BigUint::from(1u8)
        );
        assert_eq!(
            fold_lower_half(half_order.clone(), &order),
            BigUint::from(1u8)
        );
        assert_eq!(
            fold_lower_half(&half_order + BigUint::from(1u8), &order),
            BigUint::from(1u8),
        );
        assert_eq!(
            fold_lower_half(&half_order - BigUint::from(1u8), &order),
            &half_order - BigUint::from(1u8),
        );
        assert_eq!(
            fold_lower_half(&order - BigUint::from(1u8), &order),
            BigUint::from(1u8)
        );
    }

    #[test]
    fn scoped_inputs_fail_closed() {
        let private_key = Felt::from_hex("0xabc").unwrap();
        assert!(strk20_viewing_key_message_hash("0x01", "0x2").is_err());
        assert!(strk20_viewing_key_message_hash("0x1", "0x0").is_err());
        assert!(strk20_viewing_key_message_hash("not-hex", "0x2").is_err());
        assert!(derive_scoped_strk20_viewing_key(&Felt::ZERO, "0x1", "0x2").is_err());
        assert!(derive_scoped_strk20_viewing_key(&private_key, "", "0x2").is_err());
    }
}
