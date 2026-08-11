use krusty_kms_common::{ElGamalCiphertext, KmsError, Result};
use krusty_kms_crypto::StarkCurve;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Create an affine point from coordinates.
pub(super) fn create_affine_point(
    x: Felt,
    y: Felt,
) -> Result<starknet_types_core::curve::AffinePoint> {
    use starknet_types_core::curve::AffinePoint;
    AffinePoint::new(x, y).map_err(|e| {
        krusty_kms_common::KmsError::InvalidPublicKey(format!("Invalid affine point: {:?}", e))
    })
}

/// Verify that `cipher` is an ElGamal encryption of `balance` under private key `x`.
///
/// Checks `g^balance == L - R^x`.
pub(super) fn verify_cipher_encrypts_balance(
    cipher: &ElGamalCiphertext,
    x: &Felt,
    balance: u128,
    g: &ProjectivePoint,
) -> Result<()> {
    let r0_x = StarkCurve::mul(x, Some(&cipher.r));
    let r0_x_affine = StarkCurve::projective_to_affine(&r0_x)?;
    let neg_r0_x =
        StarkCurve::affine_to_projective(&create_affine_point(r0_x_affine.x(), -r0_x_affine.y())?);
    let g_b = StarkCurve::add(&cipher.l, &neg_r0_x);
    let expected_g_b = StarkCurve::mul(&Felt::from(balance), Some(g));

    let g_b_affine = StarkCurve::projective_to_affine(&g_b)?;
    let expected_g_b_affine = StarkCurve::projective_to_affine(&expected_g_b)?;

    if g_b_affine != expected_g_b_affine {
        return Err(KmsError::CryptoError(
            "storedBalance is not an encryption of balance".to_string(),
        ));
    }
    Ok(())
}
