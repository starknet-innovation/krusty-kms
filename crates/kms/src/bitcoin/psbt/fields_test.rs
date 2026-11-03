//! The BIP-174 field table: proprietary keys, value shapes of known fields
//! in every scope, and Bitcoin Core's transaction rules for previous
//! transactions. Each malformed field refuses the whole PSBT, whichever input
//! or map it is in.

// Tests index freely: a panic is a test failure, not a trapped signer.
#![allow(clippy::indexing_slicing)]

use super::tests::{
    assert_signed, fixture, funding_tx, malformed_reason, pair, sign, signer, txin, witness_utxo,
    KEY,
};
use super::*;

/// The fixture with input 1 also spending a coin with full UTXO data, so a
/// previous transaction can sit on an unlisted input.
pub(super) fn two_owned_inputs() -> Psbt {
    let mut psbt = fixture();
    let second = funding_tx(signer(KEY).script_pubkey(), 2);
    psbt.unsigned_tx.inputs[1] = txin(second.txid(), 1);
    psbt.global[0] = pair(&[GLOBAL_UNSIGNED_TX], &psbt.unsigned_tx.serialize_legacy());
    psbt.inputs[1] = vec![
        pair(&[IN_NON_WITNESS_UTXO], &second.serialize_legacy()),
        pair(&[IN_WITNESS_UTXO], &witness_utxo(&second.outputs[1])),
    ];
    psbt
}

/// Push `key` and `value` into the global map, input 1 or output 0.
fn with_pair(scope: Scope, key: &[u8], value: &[u8]) -> Psbt {
    let mut psbt = fixture();
    let map = match scope {
        Scope::Global => &mut psbt.global,
        Scope::Input => &mut psbt.inputs[1],
        Scope::Output => &mut psbt.outputs[0],
    };
    map.push(pair(key, value));
    psbt
}

const SCOPES: [Scope; 3] = [Scope::Global, Scope::Input, Scope::Output];

#[test]
fn proprietary_keys_must_parse_in_every_scope() {
    let malformed: [&[u8]; 5] = [
        &[0xfc],
        // Identifier length 5, but two identifier bytes.
        &[0xfc, 0x05, b'a', b'b'],
        &[0xfc, 0xfd, 0x03, 0x00, b'q', b's', b'b', 0x00],
        // No subtype.
        &[0xfc, 0x03, b'q', b's', b'b'],
        &[0xfc, 0x03, b'q', b's', b'b', 0xfd, 0x01, 0x00],
    ];
    for scope in SCOPES {
        for key in malformed {
            let reason = malformed_reason(&with_pair(scope, key, b"value"));
            assert!(
                reason.contains("PROPRIETARY has an invalid key"),
                "{scope:?} {key:02x?}: {reason}"
            );
        }
        // A well-formed one, with a multi-byte subtype and key data, stays.
        let key = [0xfc, 0x03, b'q', b's', b'b', 0xfd, 0x00, 0x01, 0xaa];
        let psbt = with_pair(scope, &key, b"value");
        assert_eq!(sign(&psbt, &[0]).unwrap().global, psbt.global);
    }
}

/// A depth-0 `PSBT_GLOBAL_XPUB` key for this key's public key.
fn master_xpub() -> Vec<u8> {
    // Type, then version, depth, parent fingerprint, child number, chain
    // code and key.
    [
        &[0x01, 0x04, 0x88, 0xb2, 0x1e, 0][..],
        &[0; 8],
        &[0; 32],
        &signer(KEY).public_key,
    ]
    .concat()
}

#[test]
fn key_origin_values_are_a_fingerprint_and_whole_path_elements() {
    let public_key = signer(KEY).public_key;
    let derivation_input = [&[0x06][..], &public_key].concat();
    let derivation_output = [&[0x02][..], &public_key].concat();
    let keys = [
        (Scope::Input, derivation_input.as_slice()),
        (Scope::Output, derivation_output.as_slice()),
    ];
    for (scope, key) in keys {
        for len in [0, 3, 5, 9] {
            let reason = malformed_reason(&with_pair(scope, key, &vec![7; len]));
            assert!(
                reason.contains("has a malformed value"),
                "{scope:?} {len}: {reason}"
            );
        }
        for len in [4, 8, 20] {
            assert!(sign(&with_pair(scope, key, &vec![7; len]), &[0]).is_ok());
        }
    }
    // The listed input may carry its own key origin too.
    let mut psbt = fixture();
    psbt.inputs[0].push(pair(
        &derivation_input,
        &[0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0x80],
    ));
    assert_signed(&sign(&psbt, &[0]).unwrap(), 0);
}

#[test]
fn global_xpubs_follow_bip32_depth_rules() {
    // The path has exactly as many elements as the depth byte.
    for depth in [0u8, 2] {
        let mut xpub = master_xpub();
        xpub[5] = depth;
        for elements in 0..4 {
            let value = vec![7; 4 + 4 * elements];
            let psbt = with_pair(Scope::Global, &xpub, &value);
            if elements == usize::from(depth) {
                assert!(sign(&psbt, &[0]).is_ok(), "depth {depth}");
            } else {
                let reason = malformed_reason(&psbt);
                assert!(
                    reason.contains("PSBT_GLOBAL_XPUB has a malformed value"),
                    "depth {depth}, {elements} elements: {reason}"
                );
            }
        }
        for len in [0, 3, 5] {
            let reason = malformed_reason(&with_pair(Scope::Global, &xpub, &vec![7; len]));
            assert!(reason.contains("has a malformed value"), "{len}: {reason}");
        }
    }
    // A master (depth 0) xpub has a zero parent fingerprint and child
    // number; a deeper one may have any.
    for (offset, field) in [(6, "parent fingerprint"), (10, "child number")] {
        let mut master = master_xpub();
        master[offset] = 1;
        let reason = malformed_reason(&with_pair(Scope::Global, &master, &[7; 4]));
        assert!(
            reason.contains("PSBT_GLOBAL_XPUB has an invalid key"),
            "{field}: {reason}"
        );
        let mut child = master.clone();
        child[5] = 1;
        assert!(
            sign(&with_pair(Scope::Global, &child, &[7; 8]), &[0]).is_ok(),
            "{field}"
        );
    }
    // An extended key whose public key is not on the curve is invalid.
    let mut bad_xpub = master_xpub();
    bad_xpub[46..].fill(0xff);
    let reason = malformed_reason(&with_pair(Scope::Global, &bad_xpub, &[0; 4]));
    assert!(
        reason.contains("PSBT_GLOBAL_XPUB has an invalid key"),
        "{reason}"
    );
}

#[test]
fn partial_signatures_need_a_valid_key_and_a_strict_der_signature() {
    let public_key = signer(KEY).public_key;
    let key = [&[IN_PARTIAL_SIG][..], &public_key].concat();
    let good = signer(KEY).sign_sighash_all(&[1; 32]).unwrap();
    let mut undefined_type = good.clone();
    *undefined_type.last_mut().unwrap() = 0x04;
    let mut padded_r = good.clone();
    padded_r.insert(4, 0x00);
    padded_r[1] += 1;
    padded_r[3] += 1;
    // Total length 9 with an R length of 3: the S length byte would sit one
    // past the end, which once indexed out of bounds.
    let short_s = vec![0x30, 0x06, 0x02, 0x03, 0x11, 0x22, 0x33, 0x44, 0x01];
    for value in [
        Vec::new(),
        vec![0x30, 0x01],
        undefined_type,
        padded_r,
        short_s,
    ] {
        let reason = malformed_reason(&with_pair(Scope::Input, &key, &value));
        assert!(
            reason.contains("PSBT_IN_PARTIAL_SIG has a malformed value"),
            "{reason}"
        );
    }
    let mut off_curve = key.clone();
    off_curve[2..].fill(0xff);
    let reason = malformed_reason(&with_pair(Scope::Input, &off_curve, &good));
    assert!(
        reason.contains("PSBT_IN_PARTIAL_SIG has an invalid key"),
        "{reason}"
    );
    assert!(sign(&with_pair(Scope::Input, &key, &good), &[0]).is_ok());
}

#[test]
fn every_input_field_value_is_checked_even_when_the_input_is_not_listed() {
    let cases: [(u8, &[u8], &str); 3] = [
        (IN_WITNESS_UTXO, &[0x01, 0x02], "PSBT_IN_WITNESS_UTXO"),
        (
            IN_FINAL_SCRIPTWITNESS,
            &[0x02, 0x01, 0xaa],
            "PSBT_IN_FINAL_SCRIPTWITNESS",
        ),
        (
            IN_NON_WITNESS_UTXO,
            &[0x02, 0, 0, 0],
            "malformed bitcoin data",
        ),
    ];
    for (key_type, value, reason) in cases {
        let mut psbt = fixture();
        psbt.inputs[1].retain(|pair| pair.key != [key_type]);
        psbt.inputs[1].push(pair(&[key_type], value));
        let found = malformed_reason(&psbt);
        assert!(found.contains(reason), "{key_type:#04x}: {found}");
    }
    // A well-formed finalized scriptWitness on someone else's input stays.
    let mut psbt = fixture();
    psbt.inputs[1].push(pair(&[IN_FINAL_SCRIPTWITNESS], &[0x02, 0x01, 0xaa, 0x00]));
    assert_eq!(sign(&psbt, &[0]).unwrap().inputs[1], psbt.inputs[1]);
}

#[test]
fn previous_transactions_with_a_superfluous_witness_record_are_refused() {
    // Marker and flag, then an empty witness stack for its only input.
    for input in [0, 1] {
        let mut psbt = two_owned_inputs();
        let previous = funding_tx(signer(KEY).script_pubkey(), 1 + input as u8);
        let legacy = previous.serialize_legacy();
        let (version, rest) = legacy.split_at(4);
        let (body, lock_time) = rest.split_at(rest.len() - 4);
        let superfluous = [version, &[0x00, 0x01], body, &[0x00], lock_time].concat();
        psbt.inputs[input][0] = pair(&[IN_NON_WITNESS_UTXO], &superfluous);
        let reason = malformed_reason(&psbt);
        assert!(
            reason.contains("superfluous witness record"),
            "input {input}: {reason}"
        );
    }
    assert_signed(&sign(&two_owned_inputs(), &[0, 1]).unwrap(), 1);
}

#[test]
fn serialize_inverts_parse_on_the_bip174_valid_vectors() {
    #[derive(serde::Deserialize)]
    struct Vectors {
        bip174_valid: Vec<Case>,
        bip174_signer_check_failures: Vec<Case>,
        bip174_role_examples: Vec<Case>,
    }
    #[derive(Clone, serde::Deserialize)]
    struct Case {
        psbt: String,
    }
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../../tests/fixtures/bitcoin_vectors.json")).unwrap();
    let cases = [
        vectors.bip174_valid,
        vectors.bip174_signer_check_failures,
        vectors.bip174_role_examples,
    ]
    .concat();
    assert_eq!(cases.len(), 10 + 4 + 11);
    for case in cases {
        let bytes = BASE64.decode(&case.psbt).unwrap();
        assert_eq!(Psbt::parse(&bytes).unwrap().serialize(), bytes);
    }
    let ours = fixture();
    assert_eq!(Psbt::parse(&ours.serialize()).unwrap(), ours);
}
