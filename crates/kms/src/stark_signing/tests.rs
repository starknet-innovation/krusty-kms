//! Unit tests for Stark signing and keyless verification.

use super::*;

#[test]
fn sign_stark_hash_is_deterministic() {
    let private_key = Felt::from(42u64);
    let hash = Felt::from(0x1234u64);

    let first = sign_stark_hash(&private_key, &hash).unwrap();
    let second = sign_stark_hash(&private_key, &hash).unwrap();

    assert_eq!(first, second);
}

#[test]
fn signing_with_the_public_key_matches_signing_without_it() {
    let too_big = Felt::from_hex_unchecked(
        "0x800000000000000000000000000000000000000000000000000000000000000", // 2^251
    );
    for (private_key, hash) in [(42u64, 0x1234u64), (1, 1), (0xdead_beef, 0)] {
        let (private_key, hash) = (Felt::from(private_key), Felt::from(hash));
        let expected = sign_stark_hash(&private_key, &hash).unwrap();
        let signed =
            sign_stark_hash_with_public_key(&private_key, &expected.public_key, &hash).unwrap();
        assert_eq!(signed, expected);
    }

    let key = Felt::from(42u64);
    let public_key = stark_public_key(&key).unwrap();
    let hash = Felt::from(0x1234u64);
    let other = stark_public_key(&Felt::from(43u64)).unwrap();
    // Wrong key, a felt that is no public key, and invalid signer inputs.
    assert!(sign_stark_hash_with_public_key(&key, &other, &hash).is_err());
    assert!(!is_stark_public_key(&Felt::ZERO));
    assert!(sign_stark_hash_with_public_key(&key, &Felt::ZERO, &hash).is_err());
    assert!(sign_stark_hash_with_public_key(&Felt::ZERO, &public_key, &hash).is_err());
    assert!(sign_stark_hash_with_public_key(&key, &public_key, &too_big).is_err());

    // `Ok` means "verifies under this x", not "is this private key's public
    // key": the x of (d + 2·hash/r)·G passes as well, as documented.
    let signed = sign_stark_hash(&key, &hash).unwrap();
    let order = Felt::from_hex(STARK_CURVE_ORDER_HEX).unwrap().to_biguint();
    let r_inverse = signed.r.to_biguint().modpow(&(&order - 2u8), &order);
    let twin = (key.to_biguint() + hash.to_biguint() * 2u8 * r_inverse) % &order;
    let twin = stark_public_key(&Felt::from_bytes_be_slice(&twin.to_bytes_be())).unwrap();
    assert_ne!(twin, public_key);
    let accepted = sign_stark_hash_with_public_key(&key, &twin, &hash).unwrap();
    assert_eq!((accepted.r, accepted.s), (signed.r, signed.s));
}

#[test]
fn sign_stark_hash_produces_verifiable_signature() {
    let private_key = Felt::from(42u64);
    let hash = Felt::from(0x1234u64);

    let signed = sign_stark_hash(&private_key, &hash).unwrap();
    let verified = verify(&signed.public_key, &hash, &signed.r, &signed.s).unwrap();

    assert!(verified);
}

#[test]
fn verify_stark_signature_accepts_valid_and_rejects_everything_else() {
    let hash = Felt::from(0x1234u64);
    let signed = sign_stark_hash(&Felt::from(42u64), &hash).unwrap();
    let (pk, r, s) = (signed.public_key, signed.r, signed.s);
    let other_pk = stark_public_key(&Felt::from(43u64)).unwrap();
    let too_big = Felt::from_hex_unchecked(
        "0x800000000000000000000000000000000000000000000000000000000000000", // 2^251
    );

    assert!(verify_stark_signature(&pk, &hash, &r, &s).is_ok());

    // Mismatches: in-range input that upstream reports as `Ok(false)`.
    assert_eq!(verify(&other_pk, &hash, &r, &s).ok(), Some(false));
    let mismatch = verify_stark_signature(&other_pk, &hash, &r, &s).unwrap_err();
    assert!(mismatch.to_string().contains("does not match"));
    assert!(verify_stark_signature(&pk, &(hash + Felt::ONE), &r, &s).is_err());
    assert!(verify_stark_signature(&pk, &hash, &(r + Felt::ONE), &s).is_err());
    assert!(verify_stark_signature(&pk, &hash, &r, &(s + Felt::ONE)).is_err());
    assert!(verify_stark_signature(&pk, &hash, &s, &r).is_err());
    assert!(verify_stark_signature(&other_pk, &hash, &r, &s).is_err());

    // Malformed input: an error, never a panic.
    assert!(verify_stark_signature(&pk, &hash, &Felt::ZERO, &s).is_err());
    assert!(verify_stark_signature(&pk, &hash, &r, &Felt::ZERO).is_err());
    assert!(verify_stark_signature(&pk, &hash, &too_big, &s).is_err());
    assert!(verify_stark_signature(&pk, &hash, &r, &too_big).is_err());
    assert!(verify_stark_signature(&pk, &too_big, &r, &s).is_err());
    // Zero is not an x-coordinate on the curve (see `is_stark_public_key`).
    assert!(verify_stark_signature(&Felt::ZERO, &hash, &r, &s).is_err());
}

#[test]
fn verify_stark_signature_rejects_a_zero_hash() {
    // With a zero hash, r = s = public_key satisfies the raw ECDSA
    // equation with no private key. Upstream accepts it; the wrapper must
    // not.
    let pk = stark_public_key(&Felt::from(42u64)).unwrap();
    assert!(verify(&pk, &Felt::ZERO, &pk, &pk).unwrap());
    assert!(verify_stark_signature(&pk, &Felt::ZERO, &pk, &pk).is_err());

    // An honest signature over zero is rejected too: the guard is on the hash.
    let signed = sign_stark_hash(&Felt::from(42u64), &Felt::ZERO).unwrap();
    assert!(verify_stark_signature(&pk, &Felt::ZERO, &signed.r, &signed.s).is_err());
}

#[test]
fn verify_stark_signature_rejects_cancellation_tuples_without_panicking() {
    // Inputs chosen so one candidate point `(hash/s)G ± (r/s)Q` is the
    // point at infinity. With Q = ±G and s = 1 those are `hash + r = n`
    // and `hash = r`. Upstream must report a mismatch, not unwind; this
    // pins that across dependency updates.
    let order = Felt::from_hex(STARK_CURVE_ORDER_HEX).unwrap();
    let two_pow_251 = Felt::from_hex_unchecked(
        "0x800000000000000000000000000000000000000000000000000000000000000",
    );
    let pk = stark_public_key(&Felt::ONE).unwrap();

    let hash = two_pow_251 - Felt::ONE;
    let r = order - hash;
    assert_eq!(verify(&pk, &hash, &r, &Felt::ONE).ok(), Some(false));
    assert!(verify_stark_signature(&pk, &hash, &r, &Felt::ONE).is_err());

    let same = Felt::from(12345u64);
    assert_eq!(verify(&pk, &same, &same, &Felt::ONE).ok(), Some(false));
    assert!(verify_stark_signature(&pk, &same, &same, &Felt::ONE).is_err());
}

#[test]
fn verify_stark_signature_accepts_an_external_vector() {
    // crypto-cpp vector, as carried by starknet-rust-crypto's own tests.
    let public_key = Felt::from_hex_unchecked(
        "0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
    );
    let r = Felt::from_hex_unchecked(
        "0x0411494b501a98abd8262b0da1351e17899a0c4ef23dd2f96fec5ba847310b20",
    );
    let s = Felt::from_hex_unchecked(
        "0x0405c3191ab3883ef2b763af35bc5f5d15b3b4e99461d70e84c654a351a7c81b",
    );

    assert!(verify_stark_signature(&public_key, &Felt::TWO, &r, &s).is_ok());
    assert!(verify_stark_signature(&public_key, &Felt::THREE, &r, &s).is_err());
}

#[test]
fn verify_stark_signature_accepts_either_point_with_the_public_key_x() {
    // Keys d and n - d are the two points sharing one x-coordinate.
    let hash = Felt::from(0x1234u64);
    let key = Felt::from(42u64);
    let negated_key = Felt::from_hex(STARK_CURVE_ORDER_HEX).unwrap() - key;
    let public_key = stark_public_key(&key).unwrap();
    assert_eq!(public_key, stark_public_key(&negated_key).unwrap());

    for signer in [key, negated_key] {
        let signed = sign_stark_hash(&signer, &hash).unwrap();
        assert!(verify_stark_signature(&public_key, &hash, &signed.r, &signed.s).is_ok());
    }
}

#[test]
fn verify_stark_signature_accepts_the_malleated_signature() {
    // Pins the documented malleability: callers must not key on (r, s).
    let hash = Felt::from(0x1234u64);
    let signed = sign_stark_hash(&Felt::from(42u64), &hash).unwrap();
    let order = Felt::from_hex(STARK_CURVE_ORDER_HEX).unwrap();
    let flipped = order - signed.s;

    assert!(verify_stark_signature(&signed.public_key, &hash, &signed.r, &flipped).is_ok());
}

#[test]
fn stark_public_key_matches_signature_output() {
    let private_key = Felt::from(42u64);
    let hash = Felt::from(0x1234u64);

    let public_key = stark_public_key(&private_key).unwrap();
    let signed = sign_stark_hash(&private_key, &hash).unwrap();

    assert_eq!(public_key, signed.public_key);
}

#[test]
fn zero_private_key_is_rejected_without_panicking() {
    let zero = Felt::ZERO;
    let hash = Felt::from(0x1234u64);

    assert!(stark_public_key(&zero).is_err());
    assert!(sign_stark_hash(&zero, &hash).is_err());
}

#[test]
fn curve_order_and_above_are_rejected_as_private_keys() {
    let order = Felt::from_hex(STARK_CURVE_ORDER_HEX).unwrap();
    let hash = Felt::from(0x1234u64);

    assert!(stark_public_key(&order).is_err());
    assert!(sign_stark_hash(&order, &hash).is_err());

    // A felt in [n, p) must not silently reduce mod n into a valid key.
    let above_order = order + Felt::ONE;
    assert!(stark_public_key(&above_order).is_err());
}
