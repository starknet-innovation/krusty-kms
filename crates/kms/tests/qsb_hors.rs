//! Public QSB-HORS-v1 API: mnemonic-level vectors and every refusal.
//!
//! Expected values come from the draft BIP's `reference.py` (BIP draft commit
//! 7def99c). They are public test fixtures: never fund anything derived here.

use bitcoin_hashes::{hash160, Hash as _};
use krusty_kms::qsb_hors::QSB_MAX_TRANSACTION_SIZE;
use krusty_kms::{
    derive_qsb_commitments, qsb_reveal_digest, reveal_qsb_preimages, QsbRevealIndices, QsbVault,
};
use sha2::{Digest, Sha256};

const ALL_12: &str = "all all all all all all all all all all all all";
const ABANDON_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon abandon abandon art";

/// The BIP's binding fixture: one input, one output, empty scriptSig.
const VECTOR_TX: &str =
    "02000000011111111111111111111111111111111111111111111111111111111111111111\
                         0000000000ffffffff01e803000000000000015100000000";

const ROUND0: [u16; 8] = [7, 6, 5, 4, 3, 2, 1, 0];
const ROUND1: [u16; 7] = [149, 0, 75, 3, 140, 141, 8];

fn vault(net: u8, index: u32) -> QsbVault {
    QsbVault::new(net, index).unwrap()
}

fn root(mnemonic: &str, vault: QsbVault, passphrase: Option<&str>) -> String {
    hex::encode(
        derive_qsb_commitments(mnemonic, vault, passphrase)
            .unwrap()
            .root,
    )
}

fn indices() -> QsbRevealIndices {
    QsbRevealIndices::new(&ROUND0, &ROUND1).unwrap()
}

fn tx(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

fn digest_error(transaction: &[u8]) -> String {
    qsb_reveal_digest(transaction, &indices())
        .unwrap_err()
        .to_string()
}

#[test]
fn mnemonic_roots_match_the_reference() {
    assert_eq!(
        root(ALL_12, vault(0, 0), None),
        "11f1da69fa1ca2e5f9b23a4416c7c1be994933d2d8d06d5cf80dc4be02e0d3c1"
    );
    assert_eq!(
        root(ALL_12, vault(1, 0), None),
        "c66dc23004c74f51da8beec822af7651ec818a6c964aa4036b1ef26d9186d303"
    );
    assert_eq!(
        root(ALL_12, vault(0, 0x7fff_ffff), Some("")),
        "a4b150a02e955b647ade44d3cdfd72c6faf0f0a1c0692848ab6efae4df5b3b9e"
    );
    assert_eq!(
        root(ABANDON_24, vault(1, 0x7fff_ffff), Some("TREZOR")),
        "b602dcbc49b27b4192eae2888536fe303338d0b7c99c6a474ef02bc4d776a845"
    );
}

#[test]
fn commitments_are_in_round_and_index_order() {
    let commitments = derive_qsb_commitments(ALL_12, vault(0, 0), None).unwrap();
    assert_eq!(
        hex::encode(commitments.round0[0]),
        "296a1cf12ce73e492d0c7ff22b389d2b9ca3abaa"
    );
    assert_eq!(
        hex::encode(commitments.round0[149]),
        "6d1121d94beaa3734c741ee43424ba1c9f03964e"
    );
    assert_eq!(
        hex::encode(commitments.round1[0]),
        "b84006e49e98aca181a416c4e0e4220c60248917"
    );
    assert_eq!(
        hex::encode(commitments.round1[149]),
        "2d62908d953c4fa50a41d27627413be3b875b997"
    );

    let mut root = Sha256::new_with_prefix(b"QSB-HORS-v1/root");
    for commitment in commitments.round0.iter().chain(&commitments.round1) {
        root.update(commitment);
    }
    assert_eq!(<[u8; 32]>::from(root.finalize()), commitments.root);

    let other = derive_qsb_commitments(ABANDON_24, vault(1, 0x7fff_ffff), Some("TREZOR")).unwrap();
    assert_eq!(
        hex::encode(other.round1[42]),
        "c4f4dfd8b0a5bc4894d03ed36e2ce0e968021747"
    );
}

#[test]
fn passphrase_is_nfkd_normalized_and_none_is_empty() {
    let expected = "3367188f5951b9cf5b019db72a564b58bbc1241490876c873c3778afe1729f86";
    let composed = "p\u{e4}ssw\u{f6}rd";
    let decomposed = "pa\u{308}sswo\u{308}rd";
    assert_eq!(root(ABANDON_24, vault(0, 3), Some(composed)), expected);
    assert_eq!(root(ABANDON_24, vault(0, 3), Some(decomposed)), expected);
    assert_ne!(root(ABANDON_24, vault(0, 3), None), expected);
    assert_eq!(
        derive_qsb_commitments(ALL_12, vault(0, 0), None).unwrap(),
        derive_qsb_commitments(ALL_12, vault(0, 0), Some("")).unwrap(),
    );
}

#[test]
fn reveal_returns_exactly_the_requested_preimages_in_order() {
    let revealed = reveal_qsb_preimages(ALL_12, vault(0, 0), &indices(), None).unwrap();
    let expected = [
        "0b6b0905f2690cfd7596ce9286b48e9267534453",
        "9f3294b0b99454c132864e5a09dbda411d93d6be",
        "afaf80fb765c5b87ce18243cf341b1280293c62f",
        "ee0f6da4731d989408bc284423ef1ba629016599",
        "efa5ec7eb6f3efdcba7b5a3746be9133088e81f5",
        "8e96f4778ac79de007774d090cedcdd567b455b7",
        "3bc3928691aa587d71bdde12405b3108b1169bd8",
        "830f76d7a7ad8db6374ff398c34781695bb71bdd",
        "dd4f9caba9f69ddb708fe760dad229f38fdc9064",
        "ea2c23291fccf2d89ab609839722b92b81f3c430",
        "e9e84a519babcd32940f9f25aa757913b48f170f",
        "55705494056b58f770e8e6f50d7c70cd93bb2688",
        "c3f5881c2032bfc9a1acaa1c6952c259736efaa0",
        "59bdfe764a9e2c02a8237239c4f8a84f49ba5d65",
        "61330a1af9e6388986de70cf2b5f887623f10160",
    ];
    let actual: Vec<String> = revealed.as_array().iter().map(hex::encode).collect();
    assert_eq!(actual, expected);
}

#[test]
fn every_preimage_opens_its_indexed_commitment() {
    let commitments = derive_qsb_commitments(ABANDON_24, vault(1, 9), Some("x")).unwrap();
    let revealed = reveal_qsb_preimages(ABANDON_24, vault(1, 9), &indices(), Some("x")).unwrap();
    let opened = ROUND0
        .iter()
        .map(|&i| commitments.round0[usize::from(i)])
        .chain(ROUND1.iter().map(|&i| commitments.round1[usize::from(i)]));
    for (preimage, commitment) in revealed.as_array().iter().zip(opened) {
        // An independent HASH160 (bitcoin_hashes' own SHA-256 and RIPEMD-160).
        assert_eq!(hash160::Hash::hash(preimage).to_byte_array(), commitment);
    }
}

#[test]
fn digest_matches_the_reference_for_a_two_input_transaction() {
    let transaction = tx(
        "02000000022222222222222222222222222222222222222222222222222222222222222222\
         0100000000fdffffff3333333333333333333333333333333333333333333333333333333333333333\
         0000000000ffffffff0250c30000000000001600144444444444444444444444444444444444444444\
         d204000000000000016a50f80c00",
    );
    let digest = qsb_reveal_digest(&transaction, &indices()).unwrap();
    assert_eq!(
        hex::encode(digest.binding),
        "1e2b8b7294b959ea1867713854a42b2c1431f13074c3291fe35ded6d244ffa75"
    );
    assert_eq!(
        hex::encode(digest.digest),
        "079a7372ce21711c9f8d98cd55cc8c365aff4b1bdfedcd224afb48523f62cdf7"
    );
}

#[test]
fn vaults_outside_the_profile_are_refused() {
    assert_eq!(vault(1, 0x7fff_ffff).net(), 1);
    assert_eq!(vault(0, 0x7fff_ffff).index(), 0x7fff_ffff);
    for (net, index) in [(2, 0), (0xff, 0), (0, 0x8000_0000), (1, u32::MAX)] {
        let error = QsbVault::new(net, index).unwrap_err().to_string();
        assert!(error.starts_with("Invalid derivation path: QSB"), "{error}");
    }
}

#[test]
fn reveal_indices_are_validated_and_never_sorted() {
    let indices = indices();
    assert_eq!(indices.round0(), &ROUND0);
    assert_eq!(indices.round1(), &ROUND1);
    // The same index in both rounds names two different secrets.
    QsbRevealIndices::new(&[0, 1, 2, 3, 4, 5, 6, 7], &[0, 1, 2, 3, 4, 5, 6]).unwrap();

    let refused: [(&[u16], &[u16], &str); 9] = [
        (
            &ROUND0[..7],
            &ROUND1,
            "round 0 needs exactly 8 indices, got 7",
        ),
        (
            &[0, 1, 2, 3, 4, 5, 6, 7, 8],
            &ROUND1,
            "round 0 needs exactly 8",
        ),
        (&[], &ROUND1, "round 0 needs exactly 8 indices, got 0"),
        (
            &ROUND0,
            &ROUND1[..6],
            "round 1 needs exactly 7 indices, got 6",
        ),
        (
            &ROUND0,
            &[0, 1, 2, 3, 4, 5, 6, 7],
            "round 1 needs exactly 7",
        ),
        (
            &[0, 1, 2, 3, 4, 5, 6, 0],
            &ROUND1,
            "round 0 repeats index 0",
        ),
        (&ROUND0, &[1, 2, 3, 4, 5, 6, 6], "round 1 repeats index 6"),
        (
            &[0, 1, 2, 3, 4, 5, 6, 150],
            &ROUND1,
            "round 0 index 150 is outside",
        ),
        (
            &ROUND0,
            &[1, 2, 3, 4, 5, 6, u16::MAX],
            "round 1 index 65535",
        ),
    ];
    for (round0, round1, expected) in refused {
        let error = QsbRevealIndices::new(round0, round1)
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn invalid_mnemonics_are_refused() {
    let error = derive_qsb_commitments("all all all", vault(0, 0), None).unwrap_err();
    assert!(error.to_string().starts_with("Invalid mnemonic"), "{error}");
    assert!(reveal_qsb_preimages("not a mnemonic", vault(0, 0), &indices(), None).is_err());
}

#[test]
fn scriptsigs_must_be_empty() {
    // The vector with a one-byte scriptSig (OP_1) on its only input.
    let with_script_sig = tx(&VECTOR_TX.replacen("0000000000ffffffff", "000000000151ffffffff", 1));
    assert!(digest_error(&with_script_sig).contains("input 0 has a non-empty scriptSig"));
    // Canonicalising T is the caller's job; even an encoded empty push is refused.
    let with_push = tx(&VECTOR_TX.replacen("0000000000ffffffff", "000000000100ffffffff", 1));
    assert!(digest_error(&with_push).contains("non-empty scriptSig"));
}

#[test]
fn witness_serializations_are_refused() {
    let input_and_output = &VECTOR_TX[8..VECTOR_TX.len() - 8];
    let segwit = tx(&format!("020000000001{input_and_output}0100000000"));
    assert!(digest_error(&segwit).contains("segwit marker"));
    let empty_inputs = tx("020000000001e803000000000000015100000000");
    assert!(digest_error(&empty_inputs).contains("empty input list"));
    // A witness appended to a legacy encoding is trailing data.
    let appended_witness = tx(&format!("{VECTOR_TX}0100"));
    assert!(digest_error(&appended_witness).contains("2 trailing bytes"));
}

#[test]
fn transactions_must_be_complete_and_exact() {
    let transaction = tx(VECTOR_TX);
    qsb_reveal_digest(&transaction, &indices()).unwrap();
    for len in 0..transaction.len() {
        let error = digest_error(&transaction[..len]);
        assert!(
            error.starts_with("Deserialization error: QSB transaction"),
            "{error}"
        );
    }
    let mut trailing = transaction.clone();
    trailing.push(0);
    assert!(digest_error(&trailing).contains("1 trailing bytes after locktime"));
}

/// A valid one-input, one-output `T` of exactly `size` bytes, padded with an
/// `OP_1` scriptPubKey whose length is a canonical 3-byte CompactSize.
fn transaction_of_size(size: usize) -> Vec<u8> {
    let script_len = size - 62;
    let mut transaction = tx(&VECTOR_TX[..92]);
    transaction.extend_from_slice(&[1, 0xe8, 3, 0, 0, 0, 0, 0, 0, 0xfd]);
    transaction.extend_from_slice(&u16::try_from(script_len).unwrap().to_le_bytes());
    transaction.resize(transaction.len() + script_len, 0x51);
    transaction.extend_from_slice(&[0; 4]);
    assert_eq!(transaction.len(), size);
    transaction
}

#[test]
fn transaction_size_is_bounded_with_room_for_unlocking_data() {
    qsb_reveal_digest(&transaction_of_size(QSB_MAX_TRANSACTION_SIZE), &indices()).unwrap();
    let limit = format!("exceeds the {QSB_MAX_TRANSACTION_SIZE}-byte limit");
    // The bound is checked before parsing, so far over it any bytes will do.
    let far_over = vec![0; 100 * QSB_MAX_TRANSACTION_SIZE];
    for transaction in [transaction_of_size(QSB_MAX_TRANSACTION_SIZE + 1), far_over] {
        let error = digest_error(&transaction);
        assert!(error.contains(&limit), "{error}");
    }
}

#[test]
fn non_canonical_compact_sizes_are_refused() {
    let padded_count = tx(&VECTOR_TX.replacen("0200000001", "02000000fd0100", 1));
    assert!(digest_error(&padded_count).contains("non-canonical input count"));
    let padded_script = tx(&VECTOR_TX.replacen("015100000000", "fe010000005100000000", 1));
    assert!(digest_error(&padded_script).contains("non-canonical scriptPubKey length"));
}

#[test]
fn transactions_that_can_never_confirm_are_refused() {
    let no_outputs = tx(&VECTOR_TX.replacen(
        "ffffffff01e803000000000000015100000000",
        "ffffffff0000000000",
        1,
    ));
    assert!(digest_error(&no_outputs).contains("no outputs"));

    let max_money = "0040075af0750700";
    let at_limit = tx(&VECTOR_TX.replacen("e803000000000000", max_money, 1));
    qsb_reveal_digest(&at_limit, &indices()).unwrap();
    let above_limit = tx(&VECTOR_TX.replacen("e803000000000000", "0140075af0750700", 1));
    assert!(digest_error(&above_limit).contains("output 0 value exceeds MAX_MONEY"));
    let negative = tx(&VECTOR_TX.replacen("e803000000000000", "ffffffffffffffff", 1));
    assert!(digest_error(&negative).contains("value exceeds MAX_MONEY"));
    let output = format!("{max_money}0151");
    let two_outputs = VECTOR_TX.replacen(
        "01e803000000000000015100000000",
        &format!("02{output}{output}00000000"),
        1,
    );
    assert!(digest_error(&tx(&two_outputs)).contains("total more than MAX_MONEY"));

    let input = &VECTOR_TX[10..92];
    let duplicate = tx(&VECTOR_TX.replacen("0200000001", &format!("0200000002{input}"), 1));
    assert!(digest_error(&duplicate).contains("input 1 repeats an outpoint"));
    let null = format!("{}ffffffff00ffffffff", "00".repeat(32));
    let coinbase = tx(&VECTOR_TX.replacen(input, &null, 1));
    assert!(digest_error(&coinbase).contains("input 0 spends the null outpoint"));
}
