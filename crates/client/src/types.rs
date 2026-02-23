//! Types for interacting with TONGO contracts on Starknet.

use krusty_kms_common::Result;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Cipher balance stored on-chain (ElGamal ciphertext).
#[derive(Debug, Clone)]
pub struct CipherBalance {
    pub l: ProjectivePoint,
    pub r: ProjectivePoint,
}

/// Account state from the TONGO contract.
#[derive(Debug, Clone)]
pub struct AccountState {
    /// Current spendable balance (encrypted)
    pub balance: CipherBalance,
    /// Pending balance from transfers (encrypted)
    pub pending: CipherBalance,
    /// Account nonce
    pub nonce: Felt,
}

/// Decrypted account state.
#[derive(Debug, Clone)]
pub struct DecryptedAccountState {
    /// Current spendable balance (plaintext)
    pub balance: u128,
    /// Pending balance from transfers (plaintext)
    pub pending: u128,
    /// Account nonce
    pub nonce: Felt,
}

/// Decrypt a cipher balance using ElGamal decryption.
///
/// Given C = (L, R) = (g^m * y^r, g^r), where:
/// - g is the generator
/// - m is the message (balance)
/// - y is the public key
/// - r is the random nonce
///
/// We can decrypt by computing: m = L / R^x, where x is the private key.
///
/// # Cyclomatic Complexity: 3
pub fn decrypt_cipher_balance(
    private_key: &Felt,
    cipher: &CipherBalance,
) -> Result<u128> {
    // Calculate R^x (scalar multiplication)
    let r_x = multiply_point(&cipher.r, private_key)?;

    // Calculate L - R^x to get g^m
    let g_m = subtract_points(&cipher.l, &r_x)?;

    // Perform discrete log to recover m
    // For small values (typical balances), we use brute force
    let balance = discrete_log_brute_force(&g_m)?;

    Ok(balance)
}

/// Multiply a point by a scalar.
fn multiply_point(point: &ProjectivePoint, scalar: &Felt) -> Result<ProjectivePoint> {
    // Perform scalar multiplication using double-and-add
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

    Ok(result.unwrap_or(point.clone()))
}

/// Subtract two points (add the inverse).
fn subtract_points(a: &ProjectivePoint, b: &ProjectivePoint) -> Result<ProjectivePoint> {
    // Negate b by negating the y-coordinate
    let b_affine = b.to_affine()
        .map_err(|_| krusty_kms_common::KmsError::CryptoError("Invalid point (identity)".to_string()))?;

    let neg_y = Felt::ZERO - b_affine.y();
    let neg_b = ProjectivePoint::from_affine(b_affine.x(), neg_y)
        .map_err(|_| krusty_kms_common::KmsError::CryptoError("Invalid negated point".to_string()))?;

    Ok(a + &neg_b)
}

/// Recover the discrete log m from g^m using brute force.
///
/// This works for small values (up to ~10^12), which is sufficient for
/// typical TONGO balances.
///
/// # Cyclomatic Complexity: 3
fn discrete_log_brute_force(g_m: &ProjectivePoint) -> Result<u128> {
    // Use the standard Stark curve generator from krusty-kms-crypto
    let generator = krusty_kms_crypto::StarkCurve::GENERATOR;

    // Try to convert to affine - if it fails, it's the identity (balance = 0)
    if g_m.to_affine().is_err() {
        return Ok(0);
    }

    // Brute force search up to MAX_SEARCH
    const MAX_SEARCH: u128 = 1_000_000_000_000; // 1 trillion
    let mut current = generator.clone();

    for i in 1..=MAX_SEARCH {
        if points_equal(&current, g_m) {
            return Ok(i);
        }
        current = &current + &generator;

        // Early exit if we've gone past reasonable balance values
        if i > 1_000_000 && i % 1_000_000 == 0 {
            // Check every million after the first million
        }
    }

    Err(krusty_kms_common::KmsError::CryptoError(
        format!("Failed to recover balance (discrete log not found within search limit)")
    ))
}

/// Check if two points are equal.
fn points_equal(a: &ProjectivePoint, b: &ProjectivePoint) -> bool {
    match (a.to_affine(), b.to_affine()) {
        (Ok(a_aff), Ok(b_aff)) => {
            a_aff.x() == b_aff.x() && a_aff.y() == b_aff.y()
        }
        (Err(_), Err(_)) => true, // Both are identity
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_zero_balance() {
        // Create a cipher balance for 0: (y^r, g^r)
        let private_key = Felt::from(12345u64);

        // Generate public key
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let generator = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        let public_key = multiply_point(&generator, &private_key).unwrap();

        // Encrypt 0: C = (y^r, g^r) for some random r
        let r = Felt::from(999u64);
        let r_point = multiply_point(&generator, &r).unwrap();
        let y_r = multiply_point(&public_key, &r).unwrap();

        let cipher = CipherBalance {
            l: y_r,
            r: r_point,
        };

        let decrypted = decrypt_cipher_balance(&private_key, &cipher).unwrap();
        assert_eq!(decrypted, 0);
    }

    #[test]
    fn test_point_subtraction() {
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let g = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        // g - g should give identity
        let result = subtract_points(&g, &g).unwrap();
        assert!(result.to_affine().is_err());
    }

    #[test]
    fn test_points_equal_same_point() {
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let g = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        assert!(points_equal(&g, &g));
    }

    #[test]
    fn test_points_equal_different_points() {
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let g = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        let g2 = &g + &g;
        assert!(!points_equal(&g, &g2));
    }

    #[test]
    fn test_points_equal_both_identity() {
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let g = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        // g - g = identity
        let id1 = subtract_points(&g, &g).unwrap();
        let id2 = subtract_points(&g, &g).unwrap();

        assert!(points_equal(&id1, &id2));
    }

    #[test]
    fn test_points_equal_one_identity() {
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let g = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        // g - g = identity
        let identity = subtract_points(&g, &g).unwrap();

        // One identity, one not
        assert!(!points_equal(&g, &identity));
        assert!(!points_equal(&identity, &g));
    }

    #[test]
    fn test_multiply_point_by_one() {
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let g = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        let result = multiply_point(&g, &Felt::ONE).unwrap();
        assert!(points_equal(&result, &g));
    }

    #[test]
    fn test_multiply_point_by_two() {
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let g = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        let result = multiply_point(&g, &Felt::TWO).unwrap();
        let expected = &g + &g;
        assert!(points_equal(&result, &expected));
    }

    #[test]
    fn test_discrete_log_small_value() {
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let g = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        // Test discrete log for small value (1)
        let result = discrete_log_brute_force(&g).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn test_discrete_log_value_5() {
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let g = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        // Compute 5*g
        let five_g = multiply_point(&g, &Felt::from(5u64)).unwrap();

        let result = discrete_log_brute_force(&five_g).unwrap();
        assert_eq!(result, 5);
    }

    #[test]
    fn test_decrypt_small_balance() {
        let private_key = Felt::from(12345u64);

        // Use the generator
        let g_x = Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
            .unwrap();
        let g_y = Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
            .unwrap();
        let generator = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        // Compute public key y = g^x
        let public_key = multiply_point(&generator, &private_key).unwrap();

        // Encrypt balance 5: C = (g^5 * y^r, g^r)
        let r = Felt::from(999u64);
        let r_point = multiply_point(&generator, &r).unwrap(); // g^r
        let y_r = multiply_point(&public_key, &r).unwrap(); // y^r
        let g_m = multiply_point(&generator, &Felt::from(5u64)).unwrap(); // g^5
        let l = &g_m + &y_r; // g^5 * y^r

        let cipher = CipherBalance {
            l,
            r: r_point,
        };

        let decrypted = decrypt_cipher_balance(&private_key, &cipher).unwrap();
        assert_eq!(decrypted, 5);
    }
}
