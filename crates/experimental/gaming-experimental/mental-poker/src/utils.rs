//! Utility functions for curve point operations.
//!
//! This module provides common curve point operations used throughout
//! the mental poker protocol implementation.

use crate::error::{MentalPokerError, Result};
use krusty_kms_crypto::StarkCurve;
use starknet_types_core::curve::ProjectivePoint;

/// Negate a curve point.
///
/// For a point P = (x, y), returns -P = (x, -y).
///
/// # Errors
/// Returns `MentalPokerError::InvalidPoint` if the point cannot be converted
/// to affine coordinates or if the negated point is invalid.
///
/// # Example
/// ```
/// use mental_poker::utils::negate_point;
/// use krusty_kms_crypto::StarkCurve;
/// use starknet_types_core::felt::Felt;
///
/// let point = StarkCurve::mul_generator(&Felt::from(42u64));
/// let negated = negate_point(&point).unwrap();
///
/// // P + (-P) should equal identity
/// let sum = StarkCurve::add(&point, &negated);
/// assert!(StarkCurve::is_infinity(&sum));
/// ```
pub fn negate_point(point: &ProjectivePoint) -> Result<ProjectivePoint> {
    // Handle identity point specially - negation of identity is identity
    if StarkCurve::is_infinity(point) {
        return Ok(ProjectivePoint::identity());
    }

    let affine = StarkCurve::projective_to_affine(point)?;
    ProjectivePoint::from_affine(affine.x(), -affine.y())
        .map_err(|_| MentalPokerError::InvalidPoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_types_core::felt::Felt;

    #[test]
    fn test_negate_point_generator() {
        // Negate the generator point
        let g = StarkCurve::GENERATOR;
        let neg_g = negate_point(&g).expect("Negation should succeed");

        // g + (-g) = identity
        let sum = StarkCurve::add(&g, &neg_g);
        assert!(
            StarkCurve::is_infinity(&sum),
            "G + (-G) should equal identity"
        );
    }

    #[test]
    fn test_negate_point_arbitrary() {
        // Test with an arbitrary point
        let scalar = Felt::from(12345u64);
        let point = StarkCurve::mul_generator(&scalar);
        let neg_point = negate_point(&point).expect("Negation should succeed");

        // P + (-P) = identity
        let sum = StarkCurve::add(&point, &neg_point);
        assert!(
            StarkCurve::is_infinity(&sum),
            "P + (-P) should equal identity"
        );
    }

    #[test]
    fn test_negate_point_identity() {
        // Negation of identity should be identity
        let identity = ProjectivePoint::identity();
        let neg_identity = negate_point(&identity).expect("Negation of identity should succeed");

        assert!(
            StarkCurve::is_infinity(&neg_identity),
            "Negation of identity should be identity"
        );
    }

    #[test]
    fn test_negate_point_double_negation() {
        // Double negation should return to original point
        let scalar = Felt::from(9999u64);
        let original = StarkCurve::mul_generator(&scalar);
        let negated = negate_point(&original).expect("First negation should succeed");
        let double_negated = negate_point(&negated).expect("Second negation should succeed");

        // Convert to affine to compare (projective points may have different representations)
        let original_affine = StarkCurve::projective_to_affine(&original).unwrap();
        let double_negated_affine = StarkCurve::projective_to_affine(&double_negated).unwrap();

        assert_eq!(
            original_affine, double_negated_affine,
            "Double negation should return to original point"
        );
    }

    #[test]
    fn test_negate_point_preserves_x_coordinate() {
        // Negation should preserve x coordinate
        let scalar = Felt::from(42u64);
        let point = StarkCurve::mul_generator(&scalar);
        let neg_point = negate_point(&point).expect("Negation should succeed");

        let point_affine = StarkCurve::projective_to_affine(&point).unwrap();
        let neg_point_affine = StarkCurve::projective_to_affine(&neg_point).unwrap();

        assert_eq!(
            point_affine.x(),
            neg_point_affine.x(),
            "X coordinate should be preserved after negation"
        );
    }

    #[test]
    fn test_negate_point_flips_y_coordinate() {
        // Negation should flip y coordinate (y becomes -y mod p)
        let scalar = Felt::from(42u64);
        let point = StarkCurve::mul_generator(&scalar);
        let neg_point = negate_point(&point).expect("Negation should succeed");

        let point_affine = StarkCurve::projective_to_affine(&point).unwrap();
        let neg_point_affine = StarkCurve::projective_to_affine(&neg_point).unwrap();

        // y + (-y) should equal 0 mod p
        let y_sum = point_affine.y() + neg_point_affine.y();
        assert_eq!(y_sum, Felt::ZERO, "y + (-y) should equal 0");
    }

    #[test]
    fn test_negate_point_multiple_points() {
        // Test negation on multiple points
        for i in 1u64..=10 {
            let scalar = Felt::from(i * 1000);
            let point = StarkCurve::mul_generator(&scalar);
            let neg_point = negate_point(&point).expect(&format!("Negation {} should succeed", i));

            let sum = StarkCurve::add(&point, &neg_point);
            assert!(
                StarkCurve::is_infinity(&sum),
                "P + (-P) should equal identity for point {}",
                i
            );
        }
    }
}
