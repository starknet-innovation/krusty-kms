//! The fixed-size BIP-32 and grinding code must be byte-identical to the
//! big-integer code it replaced. That code's arithmetic is kept here as the
//! reference (with the `hmac` crate for HMAC), and both run on deterministic
//! pseudorandom and edge-case inputs.

use super::*;
use ::hmac::{Hmac, KeyInit, Mac};
use num_bigint::BigUint;
use num_traits::Num;

const CURVE_ORDER: &str = "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";
const SECP256K1_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

fn reference_master_key(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    (
        result[..32].try_into().unwrap(),
        result[32..].try_into().unwrap(),
    )
}

fn reference_child(key: &[u8; 32], chain: &[u8; 32], index: u32) -> Result<([u8; 32], [u8; 32])> {
    let mut mac = Hmac::<Sha512>::new_from_slice(chain).unwrap();
    if index & 0x8000_0000 != 0 {
        mac.update(&[0x00]);
        mac.update(key);
    } else {
        let signing_key = SigningKey::from_bytes(key.into())
            .map_err(|e| KmsError::CryptoError(format!("Invalid secp256k1 key: {}", e)))?;
        mac.update(signing_key.verifying_key().to_sec1_point(true).as_bytes());
    }
    mac.update(&index.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let n = BigUint::from_str_radix(SECP256K1_N, 16).unwrap();
    let il = BigUint::from_bytes_be(&result[..32]);
    if il >= n {
        return Err(KmsError::CryptoError("IL >= n".to_string()));
    }
    let child = (il + BigUint::from_bytes_be(key)) % &n;
    if child == BigUint::from(0u32) {
        return Err(KmsError::CryptoError("zero".to_string()));
    }
    let child_bytes = child.to_bytes_be();
    let mut derived = [0u8; 32];
    let start = 32 - child_bytes.len().min(32);
    derived[start..].copy_from_slice(&child_bytes[..child_bytes.len().min(32)]);
    Ok((derived, result[32..].try_into().unwrap()))
}

fn reference_max_allowed() -> BigUint {
    let stark_order = BigUint::from_str_radix(CURVE_ORDER, 16).unwrap();
    let two256 = BigUint::from(1u32) << 256;
    &two256 - (&two256 % &stark_order)
}

fn reference_grind(key_seed: &[u8; 32]) -> Result<Felt> {
    let stark_order = BigUint::from_str_radix(CURVE_ORDER, 16).unwrap();
    let max_allowed = reference_max_allowed();
    for i in 0u8..=255 {
        let mut hasher = Sha256::new();
        hasher.update(key_seed);
        hasher.update([i]);
        let candidate = BigUint::from_bytes_be(&hasher.finalize());
        if candidate < max_allowed {
            let k = candidate % &stark_order;
            if k == BigUint::from(0u32) {
                continue;
            }
            let k_bytes = k.to_bytes_be();
            let mut padded = [0u8; 32];
            let start = 32 - k_bytes.len().min(32);
            padded[start..].copy_from_slice(&k_bytes[..k_bytes.len().min(32)]);
            return Ok(Felt::from_bytes_be_slice(&padded));
        }
    }
    Err(KmsError::CryptoError("grind".to_string()))
}

/// Deterministic pseudorandom 32-byte values: SHA-256 of a label and counter.
fn sample(label: &str, counter: u32) -> [u8; 32] {
    Sha256::new_with_prefix(label.as_bytes())
        .chain_update(counter.to_be_bytes())
        .finalize()
        .into()
}

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

#[test]
fn grind_limit_matches_the_big_integer_bound() {
    let mut limit: [u8; 32] = GRIND_LIMIT.to_be_bytes().into();
    assert_eq!(BigUint::from_bytes_be(&limit), reference_max_allowed());
    limit.zeroize();
}

#[test]
fn master_key_matches_the_hmac_crate() {
    for counter in 0..64 {
        let seed = [sample("seed-lo", counter), sample("seed-hi", counter)].concat();
        let (key, chain) = derive_master_key(&seed).unwrap();
        assert_eq!((*key, *chain), reference_master_key(&seed), "{counter}");
    }
    let (key, chain) = derive_master_key(&[0x5a; 32]).unwrap();
    assert_eq!((*key, *chain), reference_master_key(&[0x5a; 32]));
}

#[test]
fn child_derivation_matches_the_big_integer_code() {
    for counter in 0..256 {
        let key = sample("parent", counter);
        let chain = sample("chain", counter);
        for index in [counter, counter | 0x8000_0000] {
            let actual = derive_child(&key, &chain, index).map(|(k, c)| (*k, *c));
            let expected = reference_child(&key, &chain, index);
            assert_eq!(actual.ok(), expected.ok(), "{counter} {index:#x}");
        }
    }
}

#[test]
fn child_derivation_matches_at_parent_key_edges() {
    let n_minus_one = hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
    let n = hex32(SECP256K1_N);
    let edges = [
        [0u8; 32],
        hex32(&format!("{:064x}", 1)),
        n_minus_one,
        n,
        [0xff; 32],
    ];
    for (position, parent) in edges.iter().enumerate() {
        let chain = sample("edge-chain", position as u32);
        for index in [0, 7, 0x8000_0000, 0x8000_002c] {
            let actual = derive_child(parent, &chain, index).map(|(k, c)| (*k, *c));
            let expected = reference_child(parent, &chain, index);
            // Hardened children of an out-of-range parent (only reachable from an
            // unvalidated master key) derive the same reduced key; non-hardened
            // ones fail in both, as the parent is not a valid signing key.
            assert_eq!(actual.is_ok(), expected.is_ok(), "{position} {index:#x}");
            assert_eq!(actual.ok(), expected.ok(), "{position} {index:#x}");
        }
    }
}

#[test]
fn grind_key_matches_the_big_integer_code() {
    for counter in 0..2048 {
        let seed = sample("grind", counter);
        assert_eq!(
            grind_key(&seed).unwrap(),
            reference_grind(&seed).unwrap(),
            "{counter}"
        );
    }
    for seed in [[0u8; 32], [0xff; 32]] {
        assert_eq!(grind_key(&seed).unwrap(), reference_grind(&seed).unwrap());
    }
}

#[test]
fn full_paths_match_the_big_integer_code() {
    for counter in 0..32 {
        let seed = sample("path-seed", counter);
        let (mut key, mut chain) = reference_master_key(&seed);
        let path = [0x8000_002c, 0x8000_232c, 0x8000_0000 | counter, 0, counter];
        for &index in &path {
            (key, chain) = reference_child(&key, &chain, index).unwrap();
        }
        let master = derive_master_key(&seed).unwrap();
        let derived = derive_path(&master.0, &master.1, &path).unwrap();
        assert_eq!((*derived.0, *derived.1), (key, chain), "{counter}");
        assert_eq!(
            grind_key(&derived.0).unwrap(),
            reference_grind(&key).unwrap()
        );
    }
}

#[test]
fn secret_types_wipe() {
    // Fail to compile if `k256` or `crypto-bigint` lose `Zeroize`.
    fn assert_zeroize<T: Zeroize>() {}
    assert_zeroize::<Scalar>();
    assert_zeroize::<U256>();

    let mut scalar = Zeroizing::new(Scalar::ONE);
    scalar.zeroize();
    assert!(bool::from(scalar.is_zero()));
    let mut integer = Zeroizing::new(U256::MAX);
    integer.zeroize();
    assert_eq!(*integer, U256::ZERO);
}
