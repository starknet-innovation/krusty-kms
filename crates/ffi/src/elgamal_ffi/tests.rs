use super::*;

use krusty_kms_crypto::StarkCurve;
use starknet_types_core::felt::Felt;

#[test]
fn test_elgamal_encrypt_decrypt_roundtrip() {
    let message = Felt::from(10u64);
    let sk = Felt::from(42u64);
    let pk = StarkCurve::mul_generator(&sk);
    let random = Felt::from(999u64);
    let prefix = Felt::from(42u64);

    let msg_kms = felt_to_kms(&message);
    let pk_kms = proj_to_kms(&pk);
    let rnd_kms = felt_to_kms(&random);
    let pfx_kms = felt_to_kms(&prefix);

    let mut out_l = KmsProjectivePoint {
        x: KmsFelt { bytes: [0; 32] },
        y: KmsFelt { bytes: [0; 32] },
        z: KmsFelt { bytes: [0; 32] },
    };
    let mut out_r = out_l;

    // Two-call pattern: probe must not publish ciphertext points.
    let zero_point = out_l;
    let mut needed = 0usize;
    let rc = unsafe {
        kms_elgamal_encrypt(
            &msg_kms,
            &pk_kms,
            &rnd_kms,
            &pfx_kms,
            &mut out_l,
            &mut out_r,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    assert_eq!(rc, KMS_OK);
    assert!(needed > 0);
    assert_eq!(out_l.x.bytes, zero_point.x.bytes);
    assert_eq!(out_r.x.bytes, zero_point.x.bytes);

    // BUFFER_TOO_SMALL must also leave points untouched.
    let mut tiny = [0u8; 1];
    let mut tiny_written = 0usize;
    let rc = unsafe {
        kms_elgamal_encrypt(
            &msg_kms,
            &pk_kms,
            &rnd_kms,
            &pfx_kms,
            &mut out_l,
            &mut out_r,
            tiny.as_mut_ptr() as *mut std::ffi::c_char,
            tiny.len(),
            &mut tiny_written,
        )
    };
    assert_eq!(rc, KMS_ERR_BUFFER_TOO_SMALL);
    assert_eq!(tiny_written, needed);
    assert_eq!(out_l.x.bytes, zero_point.x.bytes);
    assert_eq!(out_r.x.bytes, zero_point.x.bytes);

    let mut proof_buf = vec![0u8; needed + 1];
    let mut proof_written = 0usize;
    let rc = unsafe {
        kms_elgamal_encrypt(
            &msg_kms,
            &pk_kms,
            &rnd_kms,
            &pfx_kms,
            &mut out_l,
            &mut out_r,
            proof_buf.as_mut_ptr() as *mut std::ffi::c_char,
            proof_buf.len(),
            &mut proof_written,
        )
    };
    assert_eq!(rc, KMS_OK);
    assert!(proof_written > 0);
    assert_eq!(proof_written, needed);
    assert_ne!(out_l.x.bytes, zero_point.x.bytes);

    // Decrypt
    let sk_kms = felt_to_kms(&sk);
    let mut out_pt = KmsProjectivePoint {
        x: KmsFelt { bytes: [0; 32] },
        y: KmsFelt { bytes: [0; 32] },
        z: KmsFelt { bytes: [0; 32] },
    };
    let rc = unsafe { kms_elgamal_decrypt(&out_l, &out_r, &sk_kms, &mut out_pt) };
    assert_eq!(rc, KMS_OK);

    // Verify decrypted point matches g^message
    let expected = StarkCurve::mul_generator(&message);
    let decrypted = kms_to_proj(&out_pt).unwrap();
    let exp_affine = StarkCurve::projective_to_affine(&expected).unwrap();
    let dec_affine = StarkCurve::projective_to_affine(&decrypted).unwrap();
    assert_eq!(exp_affine, dec_affine);
}

#[test]
fn test_elgamal_encrypt_strong_via_ffi() {
    let message = Felt::from(10u64);
    let sk = Felt::from(42u64);
    let pk = StarkCurve::mul_generator(&sk);
    let random = Felt::from(999u64);
    let prefix = Felt::from(42u64);

    let msg_kms = felt_to_kms(&message);
    let pk_kms = proj_to_kms(&pk);
    let rnd_kms = felt_to_kms(&random);
    let pfx_kms = felt_to_kms(&prefix);

    let mut out_l = KmsProjectivePoint {
        x: KmsFelt { bytes: [0; 32] },
        y: KmsFelt { bytes: [0; 32] },
        z: KmsFelt { bytes: [0; 32] },
    };
    let mut out_r = out_l;

    let mut needed = 0usize;
    let rc = unsafe {
        kms_elgamal_encrypt_strong(
            &msg_kms,
            &pk_kms,
            &rnd_kms,
            &pfx_kms,
            &mut out_l,
            &mut out_r,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    assert_eq!(rc, KMS_OK);
    assert!(needed > 0);

    let mut proof_buf = vec![0u8; needed + 1];
    let mut proof_written = 0usize;
    let rc = unsafe {
        kms_elgamal_encrypt_strong(
            &msg_kms,
            &pk_kms,
            &rnd_kms,
            &pfx_kms,
            &mut out_l,
            &mut out_r,
            proof_buf.as_mut_ptr() as *mut std::ffi::c_char,
            proof_buf.len(),
            &mut proof_written,
        )
    };
    assert_eq!(rc, KMS_OK);

    // The strong proof must verify under the strong transcript and be
    // rejected under the legacy one.
    let proof: krusty_kms_common::ElGamalProof =
        serde_json::from_slice(&proof_buf[..proof_written]).unwrap();
    let l = kms_to_proj(&out_l).unwrap();
    let r = kms_to_proj(&out_r).unwrap();
    assert!(
        ElGamal::verify_strong(&l, &r, &pk, &proof, &prefix).unwrap(),
        "strong FFI proof must verify under the strong transcript"
    );
    assert!(
        !ElGamal::verify(&l, &r, &pk, &proof, &prefix).unwrap(),
        "strong FFI proof must be rejected by the legacy transcript"
    );
}
