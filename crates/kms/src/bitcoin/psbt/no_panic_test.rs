//! No input makes the PSBT signer or the transaction parsers panic. Every
//! PSBT in BIP-174's test vectors and this crate's own signable PSBTs are
//! truncated at every offset and have every byte flipped, and each length
//! (CompactSize) byte is also set to 0x00, 0xfd and 0xff. Each result must
//! be `Ok` or `Err`.

// Tests index freely: a panic is a test failure, not a trapped signer.
#![allow(clippy::indexing_slicing)]

use super::fields_test::two_owned_inputs;
use super::tests::{fixture, signer, KEY};
use super::*;
use crate::bitcoin::tests::BIP143_UNSIGNED_TX;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn corpus() -> Vec<(String, Vec<u8>)> {
    #[derive(serde::Deserialize)]
    struct Vectors {
        bip174_invalid: Vec<Case>,
        bip174_valid: Vec<Case>,
        bip174_signer_check_failures: Vec<Case>,
        bip174_role_examples: Vec<Case>,
    }
    #[derive(serde::Deserialize)]
    struct Case {
        case: String,
        psbt: String,
    }
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../../tests/fixtures/bitcoin_vectors.json")).unwrap();
    let official = [
        vectors.bip174_invalid,
        vectors.bip174_valid,
        vectors.bip174_signer_check_failures,
        vectors.bip174_role_examples,
    ];
    let mut corpus: Vec<_> = official
        .into_iter()
        .flatten()
        // One invalid vector is a raw transaction, not base64 of a PSBT.
        .map(|case| (case.case, BASE64.decode(case.psbt).unwrap()))
        .collect();
    corpus.push(("own fixture".into(), fixture().serialize()));
    corpus.push((
        "own two-input fixture".into(),
        two_owned_inputs().serialize(),
    ));
    corpus
}

/// Read the CompactSize at `*at` in `bytes`, recording `base + *at`.
fn compact_size(
    bytes: &[u8],
    at: &mut usize,
    base: usize,
    offsets: &mut Vec<usize>,
) -> Option<usize> {
    let first = *bytes.get(*at)?;
    offsets.push(base + *at);
    let width = match first {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        small => {
            *at += 1;
            return Some(usize::from(small));
        }
    };
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(bytes.get(*at + 1..*at + 1 + width)?);
    *at += 1 + width;
    usize::try_from(u64::from_le_bytes(value)).ok()
}

/// Record the CompactSizes of a transaction (or, with `output_only`, of a
/// single output) found at `base`, as far as it parses.
fn transaction_lengths(tx: &[u8], base: usize, output_only: bool, offsets: &mut Vec<usize>) {
    let mut at = if output_only { 8 } else { 4 };
    let mut read = |at: &mut usize| compact_size(tx, at, base, offsets);
    if output_only {
        read(&mut at);
        return;
    }
    let segwit = tx.get(4..6) == Some(&[0x00, 0x01][..]);
    if segwit {
        at = 6;
    }
    let Some(inputs) = read(&mut at) else { return };
    for _ in 0..inputs.min(64) {
        at += 36;
        let Some(len) = read(&mut at) else { return };
        at += len + 4;
    }
    let Some(outputs) = read(&mut at) else { return };
    for _ in 0..outputs.min(64) {
        at += 8;
        let Some(len) = read(&mut at) else { return };
        at += len;
    }
    for _ in 0..if segwit { inputs.min(64) } else { 0 } {
        let Some(items) = read(&mut at) else { return };
        for _ in 0..items.min(64) {
            let Some(len) = read(&mut at) else { return };
            at += len;
        }
    }
}

/// Offsets of every CompactSize in a PSBT: each key length, key type and
/// value length, and the lengths inside the transactions and outputs it
/// holds, as far as it parses.
fn length_offsets(psbt: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut at = MAGIC.len();
    while at < psbt.len() {
        let Some(key_len) = compact_size(psbt, &mut at, 0, &mut offsets) else {
            break;
        };
        if key_len == 0 {
            continue;
        }
        let Some(key) = psbt.get(at..at + key_len) else {
            break;
        };
        offsets.push(at);
        at += key_len;
        let Some(value_len) = compact_size(psbt, &mut at, 0, &mut offsets) else {
            break;
        };
        let Some(value) = psbt.get(at..at + value_len) else {
            break;
        };
        match key {
            [0x00] => transaction_lengths(value, at, false, &mut offsets),
            [0x01] => transaction_lengths(value, at, true, &mut offsets),
            _ => {}
        }
        at += value_len;
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

/// Truncations at every offset, every byte flipped, and each length byte
/// also set to 0x00, 0xfd and 0xff.
fn mutations(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut mutations: Vec<_> = (0..bytes.len())
        .map(|len| (format!("truncated to {len}"), bytes[..len].to_vec()))
        .collect();
    let mut edit = |at: usize, byte: u8| {
        let mut mutated = bytes.to_vec();
        mutated[at] = byte;
        mutations.push((format!("byte {at} set to {byte:#04x}"), mutated));
    };
    let lengths = length_offsets(bytes);
    for &at in &lengths {
        for byte in [!bytes[at], 0x00, 0xfd, 0xff] {
            edit(at, byte);
        }
    }
    for (at, byte) in bytes.iter().enumerate() {
        if lengths.binary_search(&at).is_err() {
            edit(at, !byte);
        }
    }
    mutations
}

#[test]
fn no_mutation_of_a_psbt_or_transaction_panics() {
    // Set up once: `sign_bitcoin_psbt_inputs` only adds `P2wpkhSigner::new`.
    let signer = signer(KEY);
    let mut checked = 0usize;
    let mut panics = Vec::new();
    for (case, bytes) in corpus() {
        for (mutation, mutated) in mutations(&bytes) {
            // Decodes, parses and, when that succeeds, signs input 0.
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let _ = sign_with(&signer, &BASE64.encode(&mutated), &[0]);
            }));
            if outcome.is_err() {
                panics.push(format!("{case}: {mutation}"));
            }
            checked += 1;
        }
    }
    let transaction = hex::decode(BIP143_UNSIGNED_TX).unwrap();
    for (mutation, mutated) in mutations(&transaction) {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = Transaction::parse_legacy(&mutated);
            let _ = Transaction::parse_network(&mutated);
        }));
        if outcome.is_err() {
            panics.push(format!("BIP-143 transaction: {mutation}"));
        }
        checked += 1;
    }
    assert!(checked > 55_000, "only {checked} mutations");
    assert!(
        panics.is_empty(),
        "{} panics, first: {:?}",
        panics.len(),
        panics.first()
    );
}
