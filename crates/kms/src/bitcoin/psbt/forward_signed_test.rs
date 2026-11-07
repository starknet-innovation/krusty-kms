//! Handing a PSBT one key has signed on to a second signer: both keys'
//! SIGHASH_ALL partial signatures survive and verify.

// Tests index freely: a panic is a test failure, not a trapped signer.
#![allow(clippy::indexing_slicing)]

use super::tests::{
    assert_signed, encode, funding_tx, key, pair, sign, signer, txin, txout, witness_utxo, KEY,
    OTHER_KEY,
};
use super::*;
use crate::bitcoin::tests::verify;

#[test]
fn forward_signed_psbt_to_next_signer() {
    // When a PSBT has been signed by one key, the signed output can be
    // forwarded to another signer who can then sign additional inputs.
    // This tests the forward_signed transition: the signed PSBT from one
    // operation becomes the offered PSBT for the next operation.

    // Create a PSBT with two inputs: one for KEY and one for OTHER_KEY.
    let key_signer = signer(KEY);
    let other_signer = signer(OTHER_KEY);

    let key_tx = funding_tx(key_signer.script_pubkey(), 1);
    let other_tx = funding_tx(other_signer.script_pubkey(), 2);

    let unsigned_tx = Transaction {
        version: 2,
        inputs: vec![txin(key_tx.txid(), 1), txin(other_tx.txid(), 1)],
        outputs: vec![txout(90_000, [vec![0x00, 0x20], vec![3; 32]].concat())],
        lock_time: 0,
    };

    let psbt = Psbt {
        global: vec![pair(&[GLOBAL_UNSIGNED_TX], &unsigned_tx.serialize_legacy())],
        inputs: vec![
            vec![
                pair(&[IN_NON_WITNESS_UTXO], &key_tx.serialize_legacy()),
                pair(&[IN_WITNESS_UTXO], &witness_utxo(&key_tx.outputs[1])),
            ],
            vec![
                pair(&[IN_NON_WITNESS_UTXO], &other_tx.serialize_legacy()),
                pair(&[IN_WITNESS_UTXO], &witness_utxo(&other_tx.outputs[1])),
            ],
        ],
        outputs: vec![vec![]],
        unsigned_tx,
    };

    // Step 1: Sign input 0 with KEY
    let signed_by_key = sign(&psbt, &[0]).unwrap();

    // Verify KEY's signature is present
    let key_partial = [&[IN_PARTIAL_SIG][..], &key_signer.public_key].concat();
    assert!(signed_by_key.inputs[0]
        .iter()
        .any(|pair| pair.key == key_partial));
    // Input 1 should be unchanged
    assert_eq!(signed_by_key.inputs[1], psbt.inputs[1]);

    // Step 2: Forward the signed PSBT to another signer who signs input 1 with OTHER_KEY
    let signed_by_other =
        sign_bitcoin_psbt_inputs(&key(OTHER_KEY), &encode(&signed_by_key), &[1]).unwrap();
    let final_psbt = Psbt::parse(&BASE64.decode(signed_by_other).unwrap()).unwrap();

    // Verify both signatures are now present
    let other_partial = [&[IN_PARTIAL_SIG][..], &other_signer.public_key].concat();

    // Input 0 should have KEY's signature
    assert!(final_psbt.inputs[0]
        .iter()
        .any(|pair| pair.key == key_partial));
    // Input 1 should have OTHER_KEY's signature
    assert!(final_psbt.inputs[1]
        .iter()
        .any(|pair| pair.key == other_partial));

    // Verify the signatures are valid
    assert_signed(&final_psbt, 0);
    assert_signed_by_key(&final_psbt, 1, OTHER_KEY);
}

/// Helper to verify a signature from a specific key at a given input index.
fn assert_signed_by_key(psbt: &Psbt, index: usize, key_hex: &str) {
    let test_signer = signer(key_hex);
    let partial_key = [&[IN_PARTIAL_SIG][..], &test_signer.public_key].concat();
    let signature = psbt.inputs[index]
        .iter()
        .find(|pair| pair.key == partial_key)
        .map(|pair| pair.value.clone())
        .expect("partial signature");
    let amount = TxOut::parse_exact(find(&psbt.inputs[index], IN_WITNESS_UTXO).unwrap())
        .unwrap()
        .value;
    let midstate = psbt.unsigned_tx.sighash_midstate();
    let sighash = psbt
        .unsigned_tx
        .p2wpkh_sighash_all(&midstate, index, &test_signer.pubkey_hash, amount)
        .unwrap();
    verify(&test_signer, &sighash, &signature);
}
