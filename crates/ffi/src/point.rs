//! Projective/affine point conversion FFI functions.

use std::panic::catch_unwind;

use starknet_types_core::curve::AffinePoint;

use crate::error::*;
use crate::helpers::*;
use crate::types::*;

#[no_mangle]
pub unsafe extern "C" fn kms_projective_from_affine(
    affine: *const KmsAffinePoint,
    out: *mut KmsProjectivePoint,
) -> i32 {
    catch_unwind(|| {
        if affine.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        let x = kms_to_felt(&(*affine).x);
        let y = kms_to_felt(&(*affine).y);

        let ap = match AffinePoint::new(x, y) {
            Ok(ap) => ap,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        let proj = krusty_kms_crypto::StarkCurve::affine_to_projective(&ap);
        *out = proj_to_kms(&proj);
        KMS_OK
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_projective_to_affine(
    point: *const KmsProjectivePoint,
    out: *mut KmsAffinePoint,
) -> i32 {
    catch_unwind(|| {
        if point.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        let proj = kms_to_proj(&*point);
        match krusty_kms_crypto::StarkCurve::projective_to_affine(&proj) {
            Ok(ap) => {
                *out = affine_to_kms(&ap);
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}
