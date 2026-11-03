//! PSBT signing refuses oversized input, over-long index lists, and
//! preimage keys of the wrong length, through the public API only.
//!
//! The PSBTs here are built by hand: one input with no UTXO data and one
//! output. A PSBT that parses is then refused for the missing UTXO data
//! (`TransactionError`), so that error shows the parser accepted it.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use krusty_kms::sign_bitcoin_psbt_inputs;
use krusty_kms_common::KmsError;

/// `sign_bitcoin_psbt_inputs` accepts at most 4 MiB of decoded PSBT.
const MAX_PSBT_BYTES: usize = 4 * 1024 * 1024;
/// m/84'/0'/0'/0/0 of the BIP-84 test mnemonic (public, never fund it).
const KEY: &str = "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3";

fn key() -> [u8; 32] {
    hex::decode(KEY).unwrap().try_into().unwrap()
}

/// CompactSize, for the lengths these tests use.
fn compact_size(len: usize) -> Vec<u8> {
    match len {
        0..=0xfc => vec![len as u8],
        0xfd..=0xffff => [&[0xfd][..], &(len as u16).to_le_bytes()].concat(),
        _ => [&[0xfe][..], &(len as u32).to_le_bytes()].concat(),
    }
}

fn pair(key: &[u8], value: &[u8]) -> Vec<u8> {
    [
        compact_size(key.len()),
        key.to_vec(),
        compact_size(value.len()),
        value.to_vec(),
    ]
    .concat()
}

/// A one-input, one-output PSBT with the given extra input and output pairs.
fn psbt(input_pairs: &[Vec<u8>], output_pairs: &[Vec<u8>]) -> Vec<u8> {
    let unsigned_tx = [
        &[2, 0, 0, 0, 1][..],
        &[7; 32],
        &[0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 1],
        &1_000u64.to_le_bytes(),
        &[1, 0x51, 0, 0, 0, 0],
    ]
    .concat();
    [
        b"psbt\xff".to_vec(),
        pair(&[0x00], &unsigned_tx),
        vec![0],
        input_pairs.concat(),
        vec![0],
        output_pairs.concat(),
        vec![0],
    ]
    .concat()
}

fn sign(psbt: &[u8], indices: &[u32]) -> Result<String, KmsError> {
    sign_bitcoin_psbt_inputs(&key(), &BASE64.encode(psbt), indices)
}

fn is_malformed(result: Result<String, KmsError>, reason: &str) -> bool {
    matches!(result, Err(KmsError::DeserializationError(message)) if message.contains(reason))
}

#[test]
fn psbts_up_to_four_mib_parse_and_larger_ones_are_refused() {
    let base_len = psbt(&[], &[]).len();
    // A 0xf2 output pair whose value has a five-byte CompactSize length.
    let padding = |total: usize| pair(&[0xf2], &vec![0; total - base_len - 7]);

    let at_limit = psbt(&[], &[padding(MAX_PSBT_BYTES)]);
    assert_eq!(at_limit.len(), MAX_PSBT_BYTES);
    assert!(matches!(
        sign(&at_limit, &[0]),
        Err(KmsError::TransactionError(_))
    ));

    let over_limit = psbt(&[], &[padding(MAX_PSBT_BYTES + 1)]);
    assert!(is_malformed(sign(&over_limit, &[0]), "larger than"));

    // Text too long to decode within the limit is refused before decoding:
    // it is not base64 at all, yet the size is what is reported.
    let too_long = "!".repeat(MAX_PSBT_BYTES / 3 * 4 + 8);
    assert!(is_malformed(
        sign_bitcoin_psbt_inputs(&key(), &too_long, &[0]),
        "larger than"
    ));
}

#[test]
fn index_lists_longer_than_the_input_count_are_refused_up_front() {
    let psbt = psbt(&[], &[]);
    let long_list: Vec<u32> = (0..1_000).collect();
    for indices in [&[0, 0][..], &long_list] {
        let result = sign(&psbt, indices);
        let expected = format!(
            "{} PSBT inputs were listed but the PSBT has 1",
            indices.len()
        );
        assert!(
            matches!(&result, Err(KmsError::TransactionError(message)) if *message == expected),
            "{result:?}"
        );
    }
}

#[test]
fn hash_preimage_keys_must_carry_their_hash_length() {
    // RIPEMD160 and HASH160 take a 20-byte hash; SHA256 and HASH256 32 bytes.
    for (key_type, hash_len) in [(0x0a, 20), (0x0b, 32), (0x0c, 20), (0x0d, 32)] {
        for len in [0, hash_len - 1, hash_len + 1, 32 + 20 - hash_len] {
            let key = [&[key_type][..], &vec![0x11; len]].concat();
            let result = sign(&psbt(&[pair(&key, b"preimage")], &[]), &[0]);
            assert!(
                is_malformed(result, "invalid key"),
                "type {key_type:#04x} with {len} bytes"
            );
        }
        // The right length gets past the shape check to the value check:
        // 0x11 bytes are not the hash of "preimage".
        let key = [&[key_type][..], &vec![0x11; hash_len]].concat();
        let result = sign(&psbt(&[pair(&key, b"preimage")], &[]), &[0]);
        assert!(is_malformed(result, "does not hash to its key"));
    }
}
