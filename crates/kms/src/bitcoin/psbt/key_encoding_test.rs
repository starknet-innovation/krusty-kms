//! PSBT key types are minimal CompactSizes in every map, preimage values hash
//! to their keys, and a listed native P2WPKH input may not carry a redeem or
//! witness script.

use super::tests::{assert_signed, encode, fixture, key, pair, refusal, sign, signer, KEY};
use super::*;

/// A change to the fixture that must make it malformed.
type Edit = fn(&mut Psbt);

fn malformed_reason(psbt: &Psbt) -> String {
    match sign_bitcoin_psbt_inputs(&key(KEY), &encode(psbt), &[0]) {
        Err(KmsError::DeserializationError(reason)) => reason,
        other => panic!("expected a malformed PSBT, got {other:?}"),
    }
}

#[test]
fn non_minimal_key_types_are_refused_in_every_map() {
    let cases: [(&str, Edit); 6] = [
        // Type 3 in three bytes: read as one byte, it was unknown type 0xfd,
        // and the SIGHASH_NONE it carries was ignored.
        ("sighash type", |psbt| {
            psbt.inputs[0].push(pair(&[0xfd, 0x03, 0x00], &[0x02, 0, 0, 0]));
        }),
        ("finalized scriptwitness", |psbt| {
            psbt.inputs[0].push(pair(&[0xfd, 0x08, 0x00], &[0x00]));
        }),
        // The fixture's input 1 already has type 0xf0 with key data 0x01.
        ("duplicate", |psbt| {
            psbt.inputs[1].push(pair(&[0xfd, 0xf0, 0x00, 0x01], b"again"));
        }),
        ("global version", |psbt| {
            psbt.global.push(pair(&[0xfd, 0xfb, 0x00], &[2, 0, 0, 0]));
        }),
        ("output witness script", |psbt| {
            psbt.outputs[0].push(pair(&[0xfe, 0x01, 0x00, 0x00, 0x00], &[0x51]));
        }),
        ("truncated type", |psbt| {
            psbt.inputs[1].push(pair(&[0xfd, 0xf2], b"short"));
        }),
    ];
    for (case, edit) in cases {
        let mut psbt = fixture();
        edit(&mut psbt);
        let reason = malformed_reason(&psbt);
        assert!(
            reason.contains("non-canonical CompactSize") || reason.contains("needs 2 bytes"),
            "{case}: {reason}"
        );
    }
}

#[test]
fn minimal_multi_byte_unknown_types_pass_through_unchanged() {
    let mut psbt = fixture();
    // Types 0x100, 0x10000 and 2^32, each in its minimal width.
    psbt.global
        .push(pair(&[0xff, 0, 0, 0, 0, 1, 0, 0, 0], b"global"));
    psbt.inputs[0].push(pair(&[0xfd, 0x00, 0x01, 0xaa], b"listed"));
    psbt.inputs[1].push(pair(&[0xfd, 0x00, 0x01, 0xaa], b"unlisted"));
    psbt.outputs[0].push(pair(&[0xfe, 0x00, 0x00, 0x01, 0x00, 0xbb], b"output"));

    let signed = sign(&psbt, &[0]).unwrap();
    assert_signed(&signed, 0);
    assert_eq!(signed.inputs[0][..3], psbt.inputs[0][..]);
    assert_eq!(signed.inputs[1], psbt.inputs[1]);
    assert_eq!(signed.global, psbt.global);
    assert_eq!(signed.outputs, psbt.outputs);
}

#[test]
fn refuses_a_redeem_or_witness_script_on_a_listed_input() {
    for field in [IN_REDEEM_SCRIPT, IN_WITNESS_SCRIPT] {
        let mut psbt = fixture();
        psbt.inputs[0].push(pair(&[field], &signer(KEY).script_pubkey()));
        assert!(refusal(&psbt, &[0]).contains("redeem or witness script"));
    }
    // On an unlisted input they are not this signer's to judge, and stay.
    let mut psbt = fixture();
    psbt.inputs[1].push(pair(&[IN_WITNESS_SCRIPT], &[0x51]));
    assert_eq!(sign(&psbt, &[0]).unwrap().inputs[1], psbt.inputs[1]);
}

/// Each preimage type with the hash of `abc` it is keyed by (known answers).
const ABC_PREIMAGE_KEYS: [(u8, &str); 4] = [
    (0x0a, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (
        0x0b,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (0x0c, "bb1be98c142444d7a56aa3981c3942a978e4dc33"),
    (
        0x0d,
        "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358",
    ),
];

fn preimage_pair(key_type: u8, hash_hex: &str, value: &[u8]) -> Pair {
    let key = [&[key_type][..], &hex::decode(hash_hex).unwrap()].concat();
    pair(&key, value)
}

#[test]
fn preimages_that_hash_to_their_key_pass_through_unchanged() {
    let mut psbt = fixture();
    for (key_type, hash) in ABC_PREIMAGE_KEYS {
        psbt.inputs[0].push(preimage_pair(key_type, hash, b"abc"));
        psbt.inputs[1].push(preimage_pair(key_type, hash, b"abc"));
    }
    let signed = sign(&psbt, &[0]).unwrap();
    assert_signed(&signed, 0);
    assert_eq!(signed.inputs[0][..6], psbt.inputs[0][..]);
    assert_eq!(signed.inputs[1], psbt.inputs[1]);
}

#[test]
fn preimages_that_do_not_hash_to_their_key_are_refused_on_any_input() {
    for (key_type, hash) in ABC_PREIMAGE_KEYS {
        // On the signed input and on the unlisted one alike.
        for input in [0, 1] {
            let mut psbt = fixture();
            psbt.inputs[input].push(preimage_pair(key_type, hash, b"abd"));
            let reason = malformed_reason(&psbt);
            assert!(
                reason.contains("does not hash to its key"),
                "type {key_type:#04x} on input {input}: {reason}"
            );
        }
    }
}
