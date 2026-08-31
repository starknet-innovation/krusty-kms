//! Boundary tests for the ML-DSA WASM surface.
//!
//! Scope is deliberately narrow: this layer only parses hex, formats felts, and
//! chooses between an error and a `false`. Whether the *math* is right is
//! established in `krusty-kms-crypto` against the ml-dsa-cairo known-answer
//! vectors and a `fips204` cross-check, so none of that is duplicated here — a
//! second copy of a known-answer vector is a second thing to drift.
//!
//! The key below is synthetic, which is enough for every assertion here: key
//! expansion reads the first 32 bytes as `rho` and bit-unpacks the rest, so any
//! 1,952 bytes expand successfully. Nothing here needs a key anyone holds.

use super::*;
use wasm_bindgen_test::*;

const KEY_BYTES: usize = ML_DSA_PUBLIC_KEY_BYTES;
const SIG_BYTES: usize = ML_DSA_SIGNATURE_BYTES;

fn synthetic(len: usize) -> String {
    (0..len)
        .map(|i| format!("{:02x}", (i % 251) as u8))
        .collect()
}

fn synthetic_key() -> String {
    format!("0x{}", synthetic(KEY_BYTES))
}

#[wasm_bindgen_test]
fn the_commitment_is_a_felt_and_is_stable() {
    let key = synthetic_key();
    let first = ml_dsa_key_commitment_wasm(&key).expect("commitment");
    assert!(first.starts_with("0x"));
    assert!(Felt::from_hex(&first).is_ok());
    assert_ne!(first, "0x0");
    // Pure function of the key: the wallet derives an address from this, so two
    // calls disagreeing would mean two addresses for one device.
    assert_eq!(first, ml_dsa_key_commitment_wasm(&key).expect("again"));
}

#[wasm_bindgen_test]
fn the_prefix_is_optional_and_case_insensitive() {
    let bare = synthetic(KEY_BYTES);
    let expected = ml_dsa_key_commitment_wasm(&format!("0x{bare}")).expect("prefixed");
    assert_eq!(ml_dsa_key_commitment_wasm(&bare).expect("bare"), expected);
    assert_eq!(
        ml_dsa_key_commitment_wasm(&format!("0X{bare}")).expect("uppercase prefix"),
        expected
    );
}

#[wasm_bindgen_test]
fn a_wrong_length_key_is_an_error_naming_the_sizes() {
    let short = format!("0x{}", synthetic(KEY_BYTES - 1));
    let error = ml_dsa_key_commitment_wasm(&short).expect_err("short key must be refused");
    let message = format!("{error:?}");
    assert!(
        message.contains("1952"),
        "message should name the expected size: {message}"
    );
    assert!(ml_dsa_estimation_signature_wasm(&short).is_err());
}

#[wasm_bindgen_test]
fn bad_hex_is_an_error_not_a_panic() {
    assert!(ml_dsa_key_commitment_wasm("0xzz").is_err());
    assert!(ml_dsa_key_commitment_wasm("").is_err());
    assert!(ml_dsa_estimation_signature_wasm("nonsense").is_err());
}

#[wasm_bindgen_test]
fn the_estimation_signature_has_the_payload_shape() {
    let payload = ml_dsa_estimation_signature_wasm(&synthetic_key()).expect("estimation");
    assert_eq!(payload.len(), 1830);
    for felt in &payload {
        assert!(felt.starts_with("0x"), "not hex-prefixed: {felt}");
        assert!(Felt::from_hex(felt).is_ok(), "not a felt: {felt}");
    }
}

#[wasm_bindgen_test]
fn verification_answers_false_rather_than_throwing() {
    let key = synthetic_key();
    let signature = format!("0x{}", synthetic(SIG_BYTES));

    // A synthetic signature is not a signature. The point of these is that a
    // malformed argument is a `false`, never an exception a caller must catch
    // on the path that decides whether to broadcast.
    assert!(!ml_dsa_verify_wasm(&key, "0x1", &signature));
    assert!(!ml_dsa_verify_wasm("0xzz", "0x1", &signature));
    assert!(!ml_dsa_verify_wasm(&key, "not-a-felt", &signature));
    assert!(!ml_dsa_verify_wasm(&key, "0x1", "0x00"));
    assert!(!ml_dsa_verify_wasm("", "", ""));
}

#[wasm_bindgen_test]
fn the_payload_builder_refuses_a_signature_that_does_not_verify() {
    // The mirror image of the rule above: here a wrong input must *not* resolve
    // to a plausible-looking payload, because the contract cannot tell us why it
    // rejected one.
    let error = ml_dsa_signature_payload_wasm(
        &synthetic_key(),
        "0x1",
        &format!("0x{}", synthetic(SIG_BYTES)),
    )
    .expect_err("a synthetic signature must not produce a payload");
    assert!(format!("{error:?}").contains("ML-DSA payload failed"));
}

#[wasm_bindgen_test]
fn the_payload_builder_reports_a_bad_hash() {
    let error = ml_dsa_signature_payload_wasm(
        &synthetic_key(),
        "not-a-felt",
        &format!("0x{}", synthetic(SIG_BYTES)),
    )
    .expect_err("a bad hash must be refused");
    assert!(format!("{error:?}").contains("Invalid transaction hash"));
}
