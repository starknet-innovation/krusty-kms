//! Partial signatures already on a listed input: only SIGHASH_ALL ones may
//! sit next to the signature this key adds.

// Tests index freely: a panic is a test failure, not a trapped signer.
#![allow(clippy::indexing_slicing)]

use super::tests::{assert_signed, fixture, refusal, sign, signer, KEY, OTHER_KEY};
use super::*;

#[test]
fn refuses_an_existing_partial_signature_other_than_sighash_all() {
    // With no declared PSBT_IN_SIGHASH_TYPE, the parser accepts any defined
    // sighash byte; a listed input still refuses every one but SIGHASH_ALL,
    // whichever key the signature is under.
    let der = signer(OTHER_KEY).sign_sighash_all(&[1; 32]).unwrap();
    let body = &der[..der.len() - 1];
    for flag in [0x02, 0x03, 0x81, 0x82, 0x83] {
        for public_key in [signer(KEY).public_key, signer(OTHER_KEY).public_key] {
            let mut psbt = fixture();
            put_partial_signature(&mut psbt.inputs[0], &public_key, [body, &[flag]].concat());
            let reason = refusal(&psbt, &[0]);
            assert!(
                reason.contains("PSBT input 0: carries a partial signature other than SIGHASH_ALL"),
                "flag {flag:#x}: {reason}"
            );
        }
    }

    // A SIGHASH_ALL co-signature is kept, and this key's signature is added.
    let mut co_signed = fixture();
    put_partial_signature(
        &mut co_signed.inputs[0],
        &signer(OTHER_KEY).public_key,
        der.clone(),
    );
    let signed = sign(&co_signed, &[0]).unwrap();
    assert_signed(&signed, 0);
    assert!(signed.inputs[0].iter().any(|pair| pair.value == der));

    // Only listed inputs are checked: a weaker signature on an unlisted input stays.
    let mut unlisted = fixture();
    let weak = [body, &[0x82]].concat();
    put_partial_signature(
        &mut unlisted.inputs[1],
        &signer(OTHER_KEY).public_key,
        weak.clone(),
    );
    let signed = sign(&unlisted, &[0]).unwrap();
    assert_signed(&signed, 0);
    assert!(signed.inputs[1].iter().any(|pair| pair.value == weak));
}
