//! Scalar arithmetic modulo the Stark curve order.
//!
//! This module provides arithmetic operations for scalars used in elliptic curve
//! operations. Unlike Felt which operates modulo the field prime, scalars must
//! operate modulo the curve order.

use ghoul_common::Result;
use num_bigint::BigUint;
use num_traits::Num;
use starknet_types_core::felt::Felt;
use std::sync::LazyLock;
use zeroize::Zeroize;

/// Stark curve order (the order of the generator point).
/// This is the modulus for all scalar arithmetic in elliptic curve operations.
const CURVE_ORDER: &str = "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

static CURVE_ORDER_BIGUINT: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::from_str_radix(CURVE_ORDER, 16).expect("CURVE_ORDER constant must be valid hex")
});

/// Perform scalar addition modulo curve order.
///
/// # Cyclomatic Complexity: 1
pub fn scalar_add(a: &Felt, b: &Felt) -> Result<Felt> {
    let a_big = BigUint::from_bytes_be(&a.to_bytes_be());
    let b_big = BigUint::from_bytes_be(&b.to_bytes_be());

    let result = (a_big + b_big) % &*CURVE_ORDER_BIGUINT;

    let mut bytes = result.to_bytes_be();
    // Pad to 32 bytes if needed
    let result_felt = if bytes.len() < 32 {
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(&bytes);
        let felt = Felt::from_bytes_be(&padded);
        padded.zeroize();
        felt
    } else {
        Felt::from_bytes_be_slice(&bytes)
    };
    bytes.zeroize();
    Ok(result_felt)
}

/// Perform scalar multiplication modulo curve order.
///
/// # Cyclomatic Complexity: 1
pub fn scalar_mul(a: &Felt, b: &Felt) -> Result<Felt> {
    let a_big = BigUint::from_bytes_be(&a.to_bytes_be());
    let b_big = BigUint::from_bytes_be(&b.to_bytes_be());

    let result = (a_big * b_big) % &*CURVE_ORDER_BIGUINT;

    let mut bytes = result.to_bytes_be();
    // Pad to 32 bytes if needed
    let result_felt = if bytes.len() < 32 {
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(&bytes);
        let felt = Felt::from_bytes_be(&padded);
        padded.zeroize();
        felt
    } else {
        Felt::from_bytes_be_slice(&bytes)
    };
    bytes.zeroize();
    Ok(result_felt)
}

/// Reduce a Felt modulo the curve order.
///
/// # Cyclomatic Complexity: 1
pub fn reduce_scalar(a: &Felt) -> Result<Felt> {
    let a_big = BigUint::from_bytes_be(&a.to_bytes_be());
    let result = a_big % &*CURVE_ORDER_BIGUINT;

    let mut bytes = result.to_bytes_be();
    // Pad to 32 bytes if needed
    let result_felt = if bytes.len() < 32 {
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(&bytes);
        let felt = Felt::from_bytes_be(&padded);
        padded.zeroize();
        felt
    } else {
        Felt::from_bytes_be_slice(&bytes)
    };
    bytes.zeroize();
    Ok(result_felt)
}

/// Generate a cryptographically secure random scalar.
///
/// Uses `rand::thread_rng()` for cryptographic security.
/// This function generates a random 32-byte value suitable for use
/// as a scalar in cryptographic operations.
///
/// # Returns
/// A random `Felt` value that can be used as a scalar in elliptic curve operations.
///
/// # Cyclomatic Complexity: 1
pub fn random_felt() -> Felt {
    crate::random::random_felt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_add() {
        let a = Felt::from(100u64);
        let b = Felt::from(200u64);
        let result = scalar_add(&a, &b).unwrap();
        assert_eq!(result, Felt::from(300u64));
    }

    #[test]
    fn test_scalar_mul() {
        let a = Felt::from(7u64);
        let b = Felt::from(11u64);
        let result = scalar_mul(&a, &b).unwrap();
        assert_eq!(result, Felt::from(77u64));
    }
}
