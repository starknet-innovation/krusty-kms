use super::*;

fn negate_point(p: &ProjectivePoint) -> ProjectivePoint {
    let affine = StarkCurve::projective_to_affine(p).unwrap();
    StarkCurve::affine_to_projective(&create_affine_point(affine.x(), -affine.y()).unwrap())
}

#[test]
fn test_elgamal_encrypt_decrypt() {
    let message = Felt::from(10u64);
    let sk = Felt::from(42u64);
    let pk = StarkCurve::mul_generator(&sk);
    let random = Felt::from(999u64);
    let prefix = Felt::from(42u64);

    let encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

    // Verify proof
    let valid = ElGamal::verify(
        &encryption.l,
        &encryption.r,
        &pk,
        &encryption.proof,
        &prefix,
    )
    .unwrap();
    assert!(valid);

    // Decrypt
    let ciphertext = ElGamalCiphertext {
        l: encryption.l,
        r: encryption.r,
    };
    let decrypted = ElGamal::decrypt(&ciphertext, &sk).unwrap();
    let expected = StarkCurve::mul_generator(&message);

    let dec_affine = StarkCurve::projective_to_affine(&decrypted).unwrap();
    let exp_affine = StarkCurve::projective_to_affine(&expected).unwrap();

    assert_eq!(dec_affine, exp_affine);
}

#[test]
fn test_elgamal_invalid_proof() {
    let message = Felt::from(10u64);
    let sk = Felt::from(42u64);
    let pk = StarkCurve::mul_generator(&sk);
    let random = Felt::from(999u64);
    let prefix = Felt::from(42u64);

    let mut encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

    // Tamper with proof
    encryption.proof.sb = Felt::from(1u64);

    let valid = ElGamal::verify(
        &encryption.l,
        &encryption.r,
        &pk,
        &encryption.proof,
        &prefix,
    )
    .unwrap();
    assert!(!valid);
}

#[test]
fn test_elgamal_verify_invalid_challenge() {
    let message = Felt::from(10u64);
    let sk = Felt::from(42u64);
    let pk = StarkCurve::mul_generator(&sk);
    let random = Felt::from(999u64);
    let prefix = Felt::from(42u64);

    let mut encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

    // Tamper with challenge - this should fail challenge verification
    encryption.proof.c = Felt::from(999999u64);

    let valid = ElGamal::verify(
        &encryption.l,
        &encryption.r,
        &pk,
        &encryption.proof,
        &prefix,
    )
    .unwrap();
    assert!(!valid);
}

#[test]
fn test_elgamal_verify_invalid_sr() {
    let message = Felt::from(10u64);
    let sk = Felt::from(42u64);
    let pk = StarkCurve::mul_generator(&sk);
    let random = Felt::from(999u64);
    let prefix = Felt::from(42u64);

    let mut encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

    // Tamper with s_r - this should fail the first equation check
    encryption.proof.sr = Felt::from(1u64);

    let valid = ElGamal::verify(
        &encryption.l,
        &encryption.r,
        &pk,
        &encryption.proof,
        &prefix,
    )
    .unwrap();
    assert!(!valid);
}

#[test]
fn test_elgamal_decrypt_zero_message() {
    // Encrypt 0
    let message = Felt::ZERO;
    let sk = Felt::from(42u64);
    let pk = StarkCurve::mul_generator(&sk);
    let random = Felt::from(999u64);
    let prefix = Felt::from(42u64);

    let encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

    let ciphertext = ElGamalCiphertext {
        l: encryption.l,
        r: encryption.r,
    };
    let decrypted = ElGamal::decrypt(&ciphertext, &sk).unwrap();

    // g^0 should be identity or special case
    // Due to the scalar mul implementation, 0 * g = identity
    let expected = StarkCurve::mul_generator(&message);
    assert_eq!(decrypted, expected);
}

#[test]
fn test_elgamal_strong_roundtrip() {
    let message = Felt::from(10u64);
    let sk = Felt::from(42u64);
    let pk = StarkCurve::mul_generator(&sk);
    let random = Felt::from(999u64);
    let prefix = Felt::from(42u64);

    let encryption = ElGamal::encrypt_strong(&message, &pk, &random, &prefix).unwrap();

    let valid = ElGamal::verify_strong(
        &encryption.l,
        &encryption.r,
        &pk,
        &encryption.proof,
        &prefix,
    )
    .unwrap();
    assert!(valid);

    // Strong proofs must not verify under the legacy transcript and vice versa.
    let legacy_valid = ElGamal::verify(
        &encryption.l,
        &encryption.r,
        &pk,
        &encryption.proof,
        &prefix,
    )
    .unwrap();
    assert!(!legacy_valid);

    let legacy = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();
    let strong_accepts_legacy =
        ElGamal::verify_strong(&legacy.l, &legacy.r, &pk, &legacy.proof, &prefix).unwrap();
    assert!(!strong_accepts_legacy);
}

#[test]
fn test_elgamal_transcript_separation_law() {
    // Law of the abstraction: for any inputs, a strong proof must not
    // verify under the legacy transcript and a legacy proof must not
    // verify under the strong one. Fixed scalar set keeps the test
    // deterministic.
    for (m, sk, rand, prefix) in [
        (10u64, 42u64, 999u64, 42u64),
        (0, 1, 2, 3),
        (7, 0xdeadbeef, 0xcafe, 0xfeed),
        (u64::MAX, 0x12345, 777, 13),
    ] {
        let message = Felt::from(m);
        let secret = Felt::from(sk);
        let pk = StarkCurve::mul_generator(&secret);
        let random = Felt::from(rand);
        let prefix = Felt::from(prefix);

        let strong = ElGamal::encrypt_strong(&message, &pk, &random, &prefix).unwrap();
        assert!(
            ElGamal::verify_strong(&strong.l, &strong.r, &pk, &strong.proof, &prefix).unwrap(),
            "strong roundtrip failed for ({m}, {sk}, {rand}, {prefix})"
        );
        assert!(
            !ElGamal::verify(&strong.l, &strong.r, &pk, &strong.proof, &prefix).unwrap(),
            "legacy accepted a strong proof for ({m}, {sk}, {rand}, {prefix})"
        );

        let legacy = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();
        assert!(
            ElGamal::verify(&legacy.l, &legacy.r, &pk, &legacy.proof, &prefix).unwrap(),
            "legacy roundtrip failed for ({m}, {sk}, {rand}, {prefix})"
        );
        assert!(
            !ElGamal::verify_strong(&legacy.l, &legacy.r, &pk, &legacy.proof, &prefix).unwrap(),
            "strong accepted a legacy proof for ({m}, {sk}, {rand}, {prefix})"
        );
    }
}

#[test]
fn test_elgamal_strong_binds_ar_to_challenge() {
    // For ANY chosen challenge c and responses (s_b, s_r), setting
    //   AR = g^s_r - R^c          satisfies the R-leg equation, and
    //   AL = g^s_b + pk^s_r - L^c satisfies the L-leg equation.
    // Both algebraic checks therefore pass. The strong transcript still
    // rejects the proof because the crafted AL and AR are inputs to the
    // challenge hash, so the recomputed challenge cannot equal the
    // pre-chosen c.
    let message = Felt::from(10u64);
    let sk = Felt::from(42u64);
    let pk = StarkCurve::mul_generator(&sk);
    let random = Felt::from(999u64);
    let prefix = Felt::from(42u64);

    let encryption = ElGamal::encrypt_strong(&message, &pk, &random, &prefix).unwrap();
    let g = StarkCurve::generator();

    // Attacker-chosen challenge and responses.
    let c_forged = Felt::from(31337u64);
    let s_b = Felt::from(111u64);
    let s_r = Felt::from(222u64);

    let r_c = StarkCurve::mul(&c_forged, Some(&encryption.r));
    let neg_r_c = negate_point(&r_c);
    let g_sr = StarkCurve::mul(&s_r, Some(&g));
    let ar_forged = StarkCurve::add(&g_sr, &neg_r_c);

    let l_c = StarkCurve::mul(&c_forged, Some(&encryption.l));
    let neg_l_c = negate_point(&l_c);
    let g_sb = StarkCurve::mul(&s_b, Some(&g));
    let pk_sr = StarkCurve::mul(&s_r, Some(&pk));
    let al_forged = StarkCurve::add(&StarkCurve::add(&g_sb, &pk_sr), &neg_l_c);

    let forged_proof = ElGamalProof {
        al: SerializablePoint::try_from_projective(&al_forged).unwrap(),
        ar: SerializablePoint::try_from_projective(&ar_forged).unwrap(),
        sb: s_b,
        sr: s_r,
        c: c_forged,
    };

    let valid =
        ElGamal::verify_strong(&encryption.l, &encryption.r, &pk, &forged_proof, &prefix).unwrap();
    assert!(!valid, "strong transcript must reject after-the-fact AR");
}

#[test]
fn test_elgamal_strong_challenge_changes_with_ar_and_pk() {
    let message = Felt::from(10u64);
    let sk = Felt::from(42u64);
    let pk = StarkCurve::mul_generator(&sk);
    let other_pk = StarkCurve::mul_generator(&Felt::from(7u64));
    let random = Felt::from(999u64);
    let prefix = Felt::from(42u64);

    let encryption = ElGamal::encrypt_strong(&message, &pk, &random, &prefix).unwrap();

    // Same proof under a different public key must not verify: pk is part
    // of the strong transcript.
    let valid = ElGamal::verify_strong(
        &encryption.l,
        &encryption.r,
        &other_pk,
        &encryption.proof,
        &prefix,
    )
    .unwrap();
    assert!(!valid);
}

#[test]
fn test_elgamal_decrypt_zero_private_key_uses_identity_shared_secret() {
    let generator = StarkCurve::generator();
    let plaintext = Felt::from(7u64);
    let random = Felt::from(999u64);
    let ciphertext = ElGamalCiphertext {
        l: StarkCurve::mul(&plaintext, Some(&generator)),
        r: StarkCurve::mul(&random, Some(&generator)),
    };

    let decrypted = ElGamal::decrypt(&ciphertext, &Felt::ZERO).unwrap();
    let expected = StarkCurve::mul(&plaintext, Some(&generator));
    assert_eq!(decrypted, expected);
}
