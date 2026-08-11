//! Scalar arithmetic modulo the Stark curve order.
//!
//! This module provides arithmetic operations for scalars used in elliptic curve
//! operations. Unlike Felt which operates modulo the field prime, scalars must
//! operate modulo the curve order.
//!
//! All operations run in constant time with respect to the scalar values:
//! they use `crypto-bigint` Montgomery-form residues rather than variable-time
//! big-integer arithmetic, so proof responses computed from secret scalars
//! (`s = r + c*x`) do not leak key material through timing side channels.

use crypto_bigint::modular::ConstMontyForm;
use crypto_bigint::{const_monty_params, U256};
use krusty_kms_common::Result;
use starknet_types_core::felt::Felt;
use zeroize::Zeroize;

// Stark curve order (the order of the generator point) — the modulus for all
// scalar arithmetic in elliptic curve operations.
const_monty_params!(
    CurveOrder,
    U256,
    "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f"
);

type OrderResidue = ConstMontyForm<CurveOrder, { U256::LIMBS }>;

/// Convert a Felt into a Montgomery residue mod the curve order (constant time).
fn residue_from_felt(value: &Felt) -> OrderResidue {
    let mut bytes = value.to_bytes_be();
    let mut integer = U256::from_be_slice(&bytes);
    let residue = OrderResidue::new(&integer);
    integer.zeroize();
    bytes.zeroize();
    residue
}

/// Convert a Montgomery residue back into a canonical Felt (constant time).
fn felt_from_residue(residue: &OrderResidue) -> Felt {
    let mut integer = residue.retrieve();
    // crypto-bigint 0.7 returns `EncodedUint`; convert to a fixed array for Felt + zeroize.
    let mut bytes: [u8; 32] = integer.to_be_bytes().into();
    let felt = Felt::from_bytes_be(&bytes);
    bytes.zeroize();
    integer.zeroize();
    felt
}

/// Perform scalar addition modulo curve order.
///
/// # Cyclomatic Complexity: 1
pub fn scalar_add(a: &Felt, b: &Felt) -> Result<Felt> {
    let result = residue_from_felt(a) + residue_from_felt(b);
    Ok(felt_from_residue(&result))
}

/// Perform scalar subtraction modulo curve order: (a - b) mod order.
///
/// # Cyclomatic Complexity: 1
pub fn scalar_sub(a: &Felt, b: &Felt) -> Result<Felt> {
    let result = residue_from_felt(a) - residue_from_felt(b);
    Ok(felt_from_residue(&result))
}

/// Perform scalar multiplication modulo curve order.
///
/// # Cyclomatic Complexity: 1
pub fn scalar_mul(a: &Felt, b: &Felt) -> Result<Felt> {
    let result = residue_from_felt(a) * residue_from_felt(b);
    Ok(felt_from_residue(&result))
}

/// Reduce a Felt modulo the curve order.
///
/// # Cyclomatic Complexity: 1
pub fn reduce_scalar(a: &Felt) -> Result<Felt> {
    Ok(felt_from_residue(&residue_from_felt(a)))
}

/// Generate a cryptographically secure random scalar.
///
/// Uses OS-level entropy via `OsRng` for cryptographic security.
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
    use crypto_bigint::modular::ConstMontyParams;

    /// Curve order as a Felt for boundary tests.
    fn curve_order_felt() -> Felt {
        let bytes: [u8; 32] = CurveOrder::PARAMS.modulus().to_be_bytes().into();
        Felt::from_bytes_be(&bytes)
    }

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

    #[test]
    fn test_scalar_sub_wraps() {
        let a = Felt::from(1u64);
        let b = Felt::from(2u64);
        // 1 - 2 mod n == n - 1
        let expected = scalar_sub(&curve_order_felt(), &Felt::from(1u64)).unwrap();
        assert_eq!(scalar_sub(&a, &b).unwrap(), expected);
    }

    #[test]
    fn test_reduce_scalar_at_order_is_zero() {
        assert_eq!(reduce_scalar(&curve_order_felt()).unwrap(), Felt::ZERO);
    }

    #[test]
    fn test_add_reduces_mod_order() {
        // (n - 1) + 2 == 1 (mod n)
        let n_minus_1 = scalar_sub(&curve_order_felt(), &Felt::from(1u64)).unwrap();
        let result = scalar_add(&n_minus_1, &Felt::from(2u64)).unwrap();
        assert_eq!(result, Felt::from(1u64));
    }

    #[test]
    fn test_matches_previous_bigint_semantics() {
        // Cross-check against num-bigint reference arithmetic on random-ish values.
        use num_bigint::BigUint;
        use num_traits::Num;

        let order = BigUint::from_str_radix(
            "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f",
            16,
        )
        .unwrap();

        let a =
            Felt::from_hex("0x07d8c9b4e5f6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f70")
                .unwrap();
        let b =
            Felt::from_hex("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();

        let a_big = BigUint::from_bytes_be(&a.to_bytes_be());
        let b_big = BigUint::from_bytes_be(&b.to_bytes_be());

        let expected_add = (&a_big + &b_big) % &order;
        let expected_mul = (&a_big * &b_big) % &order;

        let got_add = BigUint::from_bytes_be(&scalar_add(&a, &b).unwrap().to_bytes_be());
        let got_mul = BigUint::from_bytes_be(&scalar_mul(&a, &b).unwrap().to_bytes_be());

        assert_eq!(got_add, expected_add);
        assert_eq!(got_mul, expected_mul);
    }
}
