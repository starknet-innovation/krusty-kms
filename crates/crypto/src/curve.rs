//! Elliptic curve operations on the Stark curve.

use krusty_kms_common::{KmsError, Result};
use starknet_types_core::curve::{AffinePoint, ProjectivePoint};
use starknet_types_core::felt::Felt;
use std::sync::LazyLock;

/// Wrapper for Stark curve operations with ergonomic API.
pub struct StarkCurve;

/// The G generator point of the Stark curve (lazily initialized).
static GENERATOR_INNER: LazyLock<ProjectivePoint> = LazyLock::new(|| {
    ProjectivePoint::new(
        Felt::from_raw([
            232005955912912577,
            299981207024966779,
            5884444832209845738,
            14484022957141291997,
        ]),
        Felt::from_raw([
            405578048423154473,
            18147424675297964973,
            664812301889158119,
            6241159653446987914,
        ]),
        Felt::from_raw([
            576460752303422960,
            18446744073709551615,
            18446744073709551615,
            18446744073709551585,
        ]),
    )
    .expect("Generator G is a valid curve point")
});

/// The H generator point (lazily initialized).
static GENERATOR_H_INNER: LazyLock<ProjectivePoint> = LazyLock::new(|| {
    ProjectivePoint::new(
        Felt::from_raw([
            494630544989822523,
            132181179302948286,
            16480848587684502369,
            5066196925898258193,
        ]),
        Felt::from_raw([
            56004507632539839,
            7751607942052885689,
            1452278637989274185,
            1071784586725618313,
        ]),
        Felt::from_raw([
            576460752303422960,
            18446744073709551615,
            18446744073709551615,
            18446744073709551585,
        ]),
    )
    .expect("Generator H is a valid curve point")
});

impl StarkCurve {
    /// Returns the G generator point of the Stark curve.
    #[inline]
    pub fn generator() -> ProjectivePoint {
        GENERATOR_INNER.clone()
    }

    /// Returns the H generator point (second independent generator).
    #[inline]
    pub fn generator_h() -> ProjectivePoint {
        GENERATOR_H_INNER.clone()
    }

    /// Multiply a point by a scalar using double-and-add algorithm.
    ///
    /// # Arguments
    /// * `scalar` - The scalar multiplier
    /// * `point` - The point to multiply (defaults to generator if None)
    ///
    /// # Returns
    /// The resulting point after scalar multiplication
    ///
    /// Cyclomatic Complexity: 2 (loop + conditional)
    pub fn mul(scalar: &Felt, point: Option<&ProjectivePoint>) -> ProjectivePoint {
        let base = match point {
            Some(p) => p.clone(),
            None => Self::generator(),
        };

        Self::scalar_mul(&base, scalar)
    }

    /// Multiply the generator by a scalar.
    ///
    /// Uses double-and-add algorithm for scalar multiplication.
    ///
    /// Cyclomatic Complexity: 1
    pub fn mul_generator(scalar: &Felt) -> ProjectivePoint {
        Self::scalar_mul(&Self::generator(), scalar)
    }

    /// Scalar multiplication using double-and-add algorithm.
    ///
    /// Cyclomatic Complexity: 3 (nested loops + conditional)
    fn scalar_mul(point: &ProjectivePoint, scalar: &Felt) -> ProjectivePoint {
        // Handle zero scalar: 0 * point = point at infinity
        if *scalar == Felt::ZERO {
            return ProjectivePoint::identity();
        }

        let scalar_bytes = scalar.to_bytes_be();
        let mut result: Option<ProjectivePoint> = None;
        let mut temp = point.clone();

        for byte in scalar_bytes.iter().rev() {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    result = Some(match result {
                        Some(r) => &r + &temp,
                        None => temp.clone(),
                    });
                }
                temp = &temp + &temp;
            }
        }

        result.unwrap_or_else(ProjectivePoint::identity)
    }

    /// Add two points on the curve.
    #[inline]
    pub fn add(p1: &ProjectivePoint, p2: &ProjectivePoint) -> ProjectivePoint {
        p1 + p2
    }

    /// Convert affine coordinates to projective.
    ///
    /// # Safety
    /// This function assumes the input `AffinePoint` is valid (on the curve).
    /// Since `AffinePoint::new()` validates points, this should always succeed
    /// for properly constructed `AffinePoint` values.
    ///
    /// Cyclomatic Complexity: 1
    #[inline]
    pub fn affine_to_projective(point: &AffinePoint) -> ProjectivePoint {
        // AffinePoint is already validated, so this conversion should never fail.
        // Using expect() with a clear message for defensive programming.
        ProjectivePoint::from_affine(point.x(), point.y()).expect(
            "AffinePoint was already validated; conversion to ProjectivePoint should never fail",
        )
    }

    /// Convert projective coordinates to affine.
    ///
    /// Cyclomatic Complexity: 1
    #[inline]
    pub fn projective_to_affine(point: &ProjectivePoint) -> Result<AffinePoint> {
        point.to_affine().map_err(|_| KmsError::PointAtInfinity)
    }

    /// Check if a point is the point at infinity.
    ///
    /// Cyclomatic Complexity: 1
    #[inline]
    pub fn is_infinity(point: &ProjectivePoint) -> bool {
        point.to_affine().is_err()
    }

    /// Verify a point lies on the curve.
    pub fn is_on_curve(x: Felt, y: Felt) -> bool {
        AffinePoint::new(x, y).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator() {
        let g = StarkCurve::generator();
        assert!(!StarkCurve::is_infinity(&g));

        // Stark curve generator point coordinates (hardcoded constants)
        const G_X: Felt = Felt::from_hex_unchecked(
            "0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
        );
        const G_Y: Felt = Felt::from_hex_unchecked(
            "0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f",
        );
        let generator =
            ProjectivePoint::from_affine(G_X, G_Y).expect("Generator G is a valid curve point");
        assert_eq!(generator, g);
    }

    #[test]
    pub fn generator_h() {
        // Second generator point H (from TypeScript reference)
        let h_x = Felt::from_dec_str(
            "627088272801405713560985229077786158610581355215145837257248988047835443922",
        )
        .expect("Generator H x-coordinate is a valid constant");
        let h_y = Felt::from_dec_str(
            "962306405833205337611861169387935900858447421343428280515103558221889311122",
        )
        .expect("Generator H y-coordinate is a valid constant");
        let g_h =
            ProjectivePoint::from_affine(h_x, h_y).expect("Generator H is a valid curve point");
        assert_eq!(g_h, StarkCurve::generator_h());
    }

    #[test]
    fn test_scalar_multiplication() {
        let scalar = Felt::from(7u64);
        let result = StarkCurve::mul_generator(&scalar);
        assert!(!StarkCurve::is_infinity(&result));
    }

    #[test]
    fn test_point_addition() {
        let g = StarkCurve::generator();
        let g2 = StarkCurve::add(&g, &g);
        let g2_direct = StarkCurve::mul_generator(&Felt::from(2u64));

        let affine1 = StarkCurve::projective_to_affine(&g2).unwrap();
        let affine2 = StarkCurve::projective_to_affine(&g2_direct).unwrap();

        assert_eq!(affine1, affine2);
    }

    #[test]
    fn test_scalar_mul_basic() {
        let g = StarkCurve::generator();

        // Test g^1 = g
        let g1 = StarkCurve::mul_generator(&Felt::from(1u64));
        let g_affine = StarkCurve::projective_to_affine(&g).unwrap();
        let g1_affine = StarkCurve::projective_to_affine(&g1).unwrap();

        assert_eq!(g_affine, g1_affine, "g^1 should equal g");

        // Test g^3 = g + g + g
        let g3_manual = StarkCurve::add(&StarkCurve::add(&g, &g), &g);
        let g3_scalar = StarkCurve::mul_generator(&Felt::from(3u64));

        let g3m_affine = StarkCurve::projective_to_affine(&g3_manual).unwrap();
        let g3s_affine = StarkCurve::projective_to_affine(&g3_scalar).unwrap();

        assert_eq!(g3m_affine, g3s_affine, "g^3 should equal g+g+g");
    }

    #[test]
    fn test_affine_projective_conversion() {
        let g = StarkCurve::generator();
        let affine = StarkCurve::projective_to_affine(&g).unwrap();
        let projective = StarkCurve::affine_to_projective(&affine);
        let affine2 = StarkCurve::projective_to_affine(&projective).unwrap();

        assert_eq!(affine, affine2);
    }

    #[test]
    fn test_scalar_mul_zero() {
        // Test that 0 * g = point at infinity (not g)
        let zero_result = StarkCurve::mul_generator(&Felt::ZERO);

        // The result should be the point at infinity
        assert!(
            StarkCurve::is_infinity(&zero_result),
            "0 * g should be point at infinity"
        );
        assert_eq!(
            zero_result,
            ProjectivePoint::identity(),
            "0 * g should equal identity"
        );

        // Test with arbitrary point
        let arbitrary_point = StarkCurve::mul_generator(&Felt::from(42u64));
        let zero_arbitrary = StarkCurve::mul(&Felt::ZERO, Some(&arbitrary_point));
        assert!(
            StarkCurve::is_infinity(&zero_arbitrary),
            "0 * point should be point at infinity"
        );
    }
}
