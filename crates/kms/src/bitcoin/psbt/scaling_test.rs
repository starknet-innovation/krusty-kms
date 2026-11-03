//! Signing many inputs of a large PSBT stays linear: BIP-143's transaction-
//! wide hashes are computed once, not once per signed input.

// Tests index freely: a panic is a test failure, not a trapped signer.
#![allow(clippy::indexing_slicing)]

use super::tests::{pair, signer, txin, witness_utxo, KEY};
use super::*;
use crate::bitcoin::tests::verify;
use crate::bitcoin::tx::TxIn;
use std::time::{Duration, Instant};

/// A PSBT with `total` inputs whose first `listed` spend this key's coins
/// (each with full UTXO data); the rest are foreign inputs with empty maps.
fn wide_psbt(total: u32, listed: u32) -> Psbt {
    let script = signer(KEY).script_pubkey();
    let coins: Vec<Transaction> = (0..listed)
        .map(|vout| Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: crate::bitcoin::tx::OutPoint {
                    txid: [1; 32],
                    vout,
                },
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: script.clone(),
            }],
            lock_time: 0,
        })
        .collect();
    let inputs = coins
        .iter()
        .map(|coin| txin(coin.txid(), 0))
        .chain((listed..total).map(|vout| txin([9; 32], vout)))
        .collect();
    let unsigned_tx = Transaction {
        version: 2,
        inputs,
        outputs: vec![TxOut {
            value: 500,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    let mut maps: Vec<Map> = coins
        .iter()
        .map(|coin| {
            vec![
                pair(&[IN_NON_WITNESS_UTXO], &coin.serialize_legacy()),
                pair(&[IN_WITNESS_UTXO], &witness_utxo(&coin.outputs[0])),
            ]
        })
        .collect();
    maps.resize((total) as usize, Vec::new());
    Psbt {
        global: vec![pair(&[GLOBAL_UNSIGNED_TX], &unsigned_tx.serialize_legacy())],
        unsigned_tx,
        inputs: maps,
        outputs: vec![Vec::new()],
    }
}

#[test]
fn signing_many_inputs_of_a_wide_psbt_is_linear() {
    // 60,000 inputs (about 2.6 MB) with 600 signed. Rehashing every
    // prevout and sequence for each signed input, as before, costs
    // 600 x 60,000 x 40 bytes, about 1.4 GB of double SHA-256 (well over 10 s
    // in a debug build); hashing them once costs 2.4 MB.
    let (total, listed) = (60_000, 600);
    let psbt = wide_psbt(total, listed);
    let encoded = BASE64.encode(psbt.serialize());
    let indices: Vec<u32> = (0..listed).collect();

    let started = Instant::now();
    let signed = sign_with(&signer(KEY), &encoded, &indices).unwrap();
    let elapsed = started.elapsed();
    eprintln!("signed {listed} of {total} inputs in {elapsed:?}");

    let signed = Psbt::parse(&BASE64.decode(signed).unwrap()).unwrap();
    let signer = signer(KEY);
    let midstate = signed.unsigned_tx.sighash_midstate();
    let partial_key = [&[IN_PARTIAL_SIG][..], &signer.public_key].concat();
    for index in 0..listed as usize {
        let signature = &signed.inputs[index].last().unwrap();
        assert_eq!(signature.key, partial_key);
        let sighash = signed
            .unsigned_tx
            .p2wpkh_sighash_all(&midstate, index, &signer.pubkey_hash, 1_000)
            .unwrap();
        verify(&signer, &sighash, &signature.value);
    }
    assert!(signed.inputs[listed as usize..].iter().all(Vec::is_empty));
    // Several times the linear cost on a slow runner, far below the quadratic one.
    assert!(elapsed < Duration::from_secs(8), "took {elapsed:?}");
}
