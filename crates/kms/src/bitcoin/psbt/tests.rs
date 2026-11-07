//! PSBT signing: the happy path, preservation of everything unlisted, and
//! every refusal.

// Tests index freely: a panic is a test failure, not a trapped signer.
#![allow(clippy::indexing_slicing)]

use super::*;
use crate::bitcoin::tests::verify;
use crate::bitcoin::tx::{OutPoint, TxIn};

/// m/84'/0'/0'/0/0 of the BIP-84 test mnemonic (public, never fund it).
pub(super) const KEY: &str = "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3";
/// m/84'/0'/0'/0/1 of the same mnemonic.
pub(super) const OTHER_KEY: &str =
    "2fd0affa51529f940a358ec0c50de81267d0bf5158ca61887347676946362c5b";
const AMOUNT: u64 = 100_000;

pub(super) fn key(hex_value: &str) -> [u8; 32] {
    hex::decode(hex_value).unwrap().try_into().unwrap()
}

pub(super) fn signer(hex_value: &str) -> P2wpkhSigner {
    P2wpkhSigner::new(&key(hex_value)).unwrap()
}

pub(super) fn pair(key: &[u8], value: &[u8]) -> Pair {
    Pair {
        key: key.to_vec(),
        value: value.to_vec(),
    }
}

pub(super) fn txout(value: u64, script_pubkey: Vec<u8>) -> TxOut {
    TxOut {
        value,
        script_pubkey,
    }
}

pub(super) fn txin(txid: [u8; 32], vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig: Vec::new(),
        sequence: 0xffff_fffd,
    }
}

pub(super) fn witness_utxo(output: &TxOut) -> Vec<u8> {
    let mut bytes = Vec::new();
    output.serialize_into(&mut bytes);
    bytes
}

/// A transaction whose output 1 pays `AMOUNT` to `script`.
pub(super) fn funding_tx(script: Vec<u8>, salt: u8) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![txin([salt; 32], 0)],
        outputs: vec![txout(5_000, vec![0x51]), txout(AMOUNT, script)],
        lock_time: 0,
    }
}

/// Input 0 spends this key's coin with full UTXO data; input 1 is a foreign
/// input carrying an unknown field. Global and output maps carry unknown and
/// proprietary pairs that must survive signing.
pub(super) fn fixture() -> Psbt {
    let ours = funding_tx(signer(KEY).script_pubkey(), 1);
    let unsigned_tx = Transaction {
        version: 2,
        inputs: vec![txin(ours.txid(), 1), txin([9; 32], 0)],
        outputs: vec![txout(90_000, [vec![0x00, 0x20], vec![3; 32]].concat())],
        lock_time: 0,
    };
    Psbt {
        global: vec![
            pair(&[GLOBAL_UNSIGNED_TX], &unsigned_tx.serialize_legacy()),
            pair(&[0xfc, 0x03, b'q', b's', b'b', 0x00], b"proprietary"),
        ],
        inputs: vec![
            vec![
                pair(&[IN_NON_WITNESS_UTXO], &ours.serialize_legacy()),
                pair(&[IN_WITNESS_UTXO], &witness_utxo(&ours.outputs[1])),
            ],
            vec![
                pair(&[IN_WITNESS_UTXO], &witness_utxo(&txout(7, vec![0x51]))),
                pair(&[0xf0, 0x01], b"unknown"),
            ],
        ],
        outputs: vec![vec![pair(&[0xf1], b"unknown output field")]],
        unsigned_tx,
    }
}

pub(super) fn encode(psbt: &Psbt) -> String {
    BASE64.encode(psbt.serialize())
}

pub(super) fn sign(psbt: &Psbt, indices: &[u32]) -> Result<Psbt> {
    let signed = sign_bitcoin_psbt_inputs(&key(KEY), &encode(psbt), indices)?;
    Psbt::parse(&BASE64.decode(signed).unwrap())
}

pub(super) fn assert_signed(psbt: &Psbt, index: usize) {
    let signer = signer(KEY);
    let partial_key = [&[IN_PARTIAL_SIG][..], &signer.public_key].concat();
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
        .p2wpkh_sighash_all(&midstate, index, &signer.pubkey_hash, amount)
        .unwrap();
    verify(&signer, &sighash, &signature);
}

pub(super) fn refusal(psbt: &Psbt, indices: &[u32]) -> String {
    match sign(psbt, indices) {
        Err(KmsError::TransactionError(reason)) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn signs_the_listed_input_and_leaves_everything_else_byte_identical() {
    let original = fixture();
    let signed = sign(&original, &[0]).unwrap();

    assert_signed(&signed, 0);
    assert_eq!(signed.inputs[0][..2], original.inputs[0][..]);
    assert_eq!(signed.inputs[0].len(), 3);
    assert_eq!(signed.inputs[1], original.inputs[1]);
    assert_eq!(signed.global, original.global);
    assert_eq!(signed.outputs, original.outputs);
    assert_eq!(signed.unsigned_tx, original.unsigned_tx);
}

#[test]
fn re_signing_replaces_this_keys_signature_and_is_deterministic() {
    let once = sign(&fixture(), &[0]).unwrap();
    assert_eq!(sign(&once, &[0]).unwrap(), once);

    // A well-formed signature by this key over another digest is replaced.
    let mut stale = fixture();
    let other_signature = signer(KEY).sign_sighash_all(&[1; 32]).unwrap();
    put_partial_signature(
        &mut stale.inputs[0],
        &signer(KEY).public_key,
        other_signature,
    );
    assert_eq!(sign(&stale, &[0]).unwrap(), once);
}

#[test]
fn signs_several_inputs_and_accepts_witness_serialized_previous_transactions() {
    let mut psbt = fixture();
    let second = funding_tx(signer(KEY).script_pubkey(), 2);
    psbt.unsigned_tx.inputs[1] = txin(second.txid(), 1);
    psbt.global[0] = pair(&[GLOBAL_UNSIGNED_TX], &psbt.unsigned_tx.serialize_legacy());
    // Version, segwit marker and flag, the legacy body, one witness, lock time.
    let legacy = second.serialize_legacy();
    let (body, lock_time) = legacy[4..].split_at(legacy.len() - 8);
    let segwit = [
        &legacy[..4],
        &[0x00, 0x01],
        body,
        &[0x01, 0x01, 0xaa],
        lock_time,
    ]
    .concat();
    psbt.inputs[1] = vec![
        pair(&[IN_NON_WITNESS_UTXO], &segwit),
        pair(&[IN_WITNESS_UTXO], &witness_utxo(&second.outputs[1])),
        pair(&[IN_SIGHASH_TYPE], &[0x01, 0, 0, 0]),
    ];

    let signed = sign(&psbt, &[1, 0]).unwrap();
    assert_signed(&signed, 0);
    assert_signed(&signed, 1);
}

#[test]
fn refuses_a_witness_utxo_for_another_script() {
    for script in [
        signer(OTHER_KEY).script_pubkey(),
        // This key's hash, but nested in P2SH instead of native P2WPKH.
        [
            vec![0xa9, 0x14],
            signer(KEY).pubkey_hash.to_vec(),
            vec![0x87],
        ]
        .concat(),
    ] {
        let mut psbt = fixture();
        let other = funding_tx(script, 1);
        psbt.unsigned_tx.inputs[0] = txin(other.txid(), 1);
        psbt.global[0] = pair(&[GLOBAL_UNSIGNED_TX], &psbt.unsigned_tx.serialize_legacy());
        psbt.inputs[0] = vec![
            pair(&[IN_NON_WITNESS_UTXO], &other.serialize_legacy()),
            pair(&[IN_WITNESS_UTXO], &witness_utxo(&other.outputs[1])),
        ];
        assert!(refusal(&psbt, &[0]).contains("is not this key's P2WPKH script"));
    }
}

#[test]
fn refuses_missing_utxo_data() {
    for (missing, reason) in [
        (IN_WITNESS_UTXO, "has no witness_utxo"),
        (IN_NON_WITNESS_UTXO, "has no non_witness_utxo"),
    ] {
        let mut psbt = fixture();
        psbt.inputs[0].retain(|pair| pair.key != [missing]);
        assert!(refusal(&psbt, &[0]).contains(reason));
    }
}

/// The `DeserializationError` reason when signing input 0 of `psbt`.
pub(super) fn malformed_reason(psbt: &Psbt) -> String {
    match sign_bitcoin_psbt_inputs(&key(KEY), &encode(psbt), &[0]) {
        Err(KmsError::DeserializationError(reason)) => reason,
        other => panic!("expected a malformed PSBT, got {other:?}"),
    }
}

#[test]
fn refuses_a_non_witness_utxo_that_is_not_the_spent_transaction() {
    // As Bitcoin Core does, the PSBT is malformed, whichever input it is on.
    let unrelated = funding_tx(signer(KEY).script_pubkey(), 3);
    for input in [0, 1] {
        let mut psbt = fixture();
        psbt.inputs[input].retain(|pair| pair.key != [IN_NON_WITNESS_UTXO]);
        psbt.inputs[input].push(pair(&[IN_NON_WITNESS_UTXO], &unrelated.serialize_legacy()));
        assert!(malformed_reason(&psbt).contains("is not the transaction this input spends"));
    }
}

#[test]
fn refuses_a_witness_utxo_that_lies_about_the_amount() {
    // The segwit fee attack: a witness_utxo claiming more than the real coin.
    let mut psbt = fixture();
    let inflated = txout(AMOUNT * 10, signer(KEY).script_pubkey());
    psbt.inputs[0][1] = pair(&[IN_WITNESS_UTXO], &witness_utxo(&inflated));
    assert!(refusal(&psbt, &[0]).contains("does not match the output it spends"));
}

#[test]
fn refuses_a_prevout_index_past_the_previous_outputs() {
    let mut psbt = fixture();
    psbt.unsigned_tx.inputs[0].previous_output.vout = 2;
    psbt.global[0] = pair(&[GLOBAL_UNSIGNED_TX], &psbt.unsigned_tx.serialize_legacy());
    assert!(malformed_reason(&psbt).contains("has no output at the spent index"));
}

#[test]
fn refuses_every_sighash_type_but_all() {
    let types: [&[u8]; 5] = [
        &[0x00, 0, 0, 0],
        &[0x02, 0, 0, 0],
        &[0x03, 0, 0, 0],
        &[0x81, 0, 0, 0],
        &[0x01, 0, 0, 1],
    ];
    for sighash_type in types {
        let mut psbt = fixture();
        psbt.inputs[0].push(pair(&[IN_SIGHASH_TYPE], sighash_type));
        assert!(refusal(&psbt, &[0]).contains("other than SIGHASH_ALL"));
    }
    // A value that is not 32 bits is malformed on any input.
    for input in [0, 1] {
        let mut psbt = fixture();
        psbt.inputs[input].push(pair(&[IN_SIGHASH_TYPE], &[0x01, 0, 0]));
        assert!(malformed_reason(&psbt).contains("PSBT_IN_SIGHASH_TYPE has a malformed value"));
    }
    let mut explicit_all = fixture();
    explicit_all.inputs[0].push(pair(&[IN_SIGHASH_TYPE], &[0x01, 0, 0, 0]));
    assert_signed(&sign(&explicit_all, &[0]).unwrap(), 0);
}

#[test]
fn refuses_a_finalized_input() {
    for final_field in [IN_FINAL_SCRIPTSIG, IN_FINAL_SCRIPTWITNESS] {
        let mut psbt = fixture();
        psbt.inputs[0].push(pair(&[final_field], &[0x00]));
        assert!(refusal(&psbt, &[0]).contains("already finalized"));
    }
}

#[test]
fn refuses_bad_index_lists_and_signs_nothing_when_any_input_is_refused() {
    let psbt = fixture();
    assert!(refusal(&psbt, &[]).contains("no PSBT inputs"));
    assert!(refusal(&psbt, &[2]).contains("out of range"));
    assert!(refusal(&psbt, &[u32::MAX]).contains("out of range"));
    assert!(refusal(&psbt, &[0, 0]).contains("more than once"));
    // Input 1 is not this key's, so the whole call fails.
    assert!(refusal(&psbt, &[0, 1]).contains("PSBT input 1"));
}

#[test]
fn refuses_invalid_keys_and_malformed_encodings() {
    let encoded = encode(&fixture());
    assert!(matches!(
        sign_bitcoin_psbt_inputs(&[0u8; 32], &encoded, &[0]),
        Err(KmsError::InvalidPrivateKey(_))
    ));

    let mut trailing = fixture().serialize();
    trailing.push(0x00);
    let mut version_two = fixture();
    version_two
        .global
        .push(pair(&[GLOBAL_VERSION], &[2, 0, 0, 0]));
    let mut duplicate = fixture();
    duplicate.inputs[1].push(pair(&[0xf0, 0x01], b"again"));
    let malformed_inputs = [
        format!("{encoded}\n"),
        format!("{encoded}="),
        "not base64!".to_string(),
        BASE64.encode(trailing),
        encode(&version_two),
        encode(&duplicate),
    ];
    for input in malformed_inputs {
        assert!(matches!(
            sign_bitcoin_psbt_inputs(&key(KEY), &input, &[0]),
            Err(KmsError::DeserializationError(_))
        ));
    }
}
