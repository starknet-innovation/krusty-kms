//! STRK20 privacy-pool viewing-key derivation.
//!
//! The viewing key used by the Starknet Privacy SDK is derived deterministically
//! from a Stark private key, so it never has to be persisted as a second secret.
//! This mirrors the reference TypeScript derivation exactly:
//!
//! ```text
//! vk = Pedersen(starknet_keccak("pharaoh.strk20.viewing_key.v1"), private_key)
//!        mod (n / 2) + 1
//! ```
//!
//! where `n` is the Stark curve order. The `mod (n / 2) + 1` keeps `vk` inside
//! the SDK's valid viewing-key range `[1, n/2]`.
//!
//! Keeping this in `krusty-kms` means the viewing-key crypto lives in audited
//! Rust alongside the rest of the wallet's signing and hashing, rather than in
//! ad-hoc TypeScript.

use num_bigint::BigUint;
use num_traits::Num;
use sha3::{Digest, Keccak256};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};

/// Domain separator hashed into every STRK20 viewing key.
pub const STRK20_VIEWING_KEY_DOMAIN: &str = "pharaoh.strk20.viewing_key.v1";

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

/// Derive the STRK20 viewing key from a Stark `private_key`.
///
/// The returned felt is guaranteed to be in `[1, n/2]`.
pub fn derive_strk20_viewing_key(private_key: &Felt) -> Felt {
    let domain = starknet_keccak(STRK20_VIEWING_KEY_DOMAIN.as_bytes());
    let material = Pedersen::hash(&domain, private_key);

    // `n / 2` — the inclusive upper bound for valid viewing keys.
    let max_viewing_key = BigUint::from_str_radix(CURVE_ORDER_HEX, 16)
        .expect("CURVE_ORDER_HEX is a valid hex constant")
        >> 1;

    // Reduce the Pedersen output into the viewing-key range. This is integer
    // arithmetic over the canonical felt representative, *not* field arithmetic.
    let material_uint = BigUint::from_bytes_be(&material.to_bytes_be());
    let viewing_key: BigUint = (material_uint % &max_viewing_key) + BigUint::from(1u8);

    Felt::from_bytes_be_slice(&viewing_key.to_bytes_be())
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
}
