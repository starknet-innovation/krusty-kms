//! Known-answer tests for the transaction, sighash and BIP-322 internals.
//! Public-API vectors (BIP-84, BIP-322 signatures, BIP-174) live in
//! `crates/kms/tests/bitcoin_vectors.rs`.

use super::bip322::{message_hash, to_sign, to_spend};
use super::keys::P2wpkhSigner;
use super::tx::{Reader, Transaction};
use super::*;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use krusty_kms_common::KmsError;

fn bytes(hex_value: &str) -> Vec<u8> {
    hex::decode(hex_value).unwrap()
}

fn key(hex_value: &str) -> [u8; 32] {
    bytes(hex_value).try_into().unwrap()
}

/// Txids are displayed byte-reversed.
fn display_txid(txid: [u8; 32]) -> String {
    let mut reversed = txid;
    reversed.reverse();
    hex::encode(reversed)
}

// BIP-143, "Native P2WPKH" example: the second input spends a P2WPKH output.
const BIP143_UNSIGNED_TX: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
const BIP143_PRIVATE_KEY: &str = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
const BIP143_PUBLIC_KEY: &str =
    "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357";
const BIP143_SCRIPT_PUBKEY: &str = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
const BIP143_AMOUNT: u64 = 600_000_000;
const BIP143_SIGHASH: &str = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";
const BIP322_PRIVATE_KEY: &str = "bb051cd0dda0246f33c5a9e133ebd8e7bc02a92af6c41adc131ccd7826c5b004";
const BIP143_SIGNATURE: &str = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01";

#[test]
fn bip143_native_p2wpkh_sighash_and_signature() {
    let tx = Transaction::parse_legacy(&bytes(BIP143_UNSIGNED_TX)).unwrap();
    assert_eq!(tx.serialize_legacy(), bytes(BIP143_UNSIGNED_TX));

    let signer = P2wpkhSigner::new(&key(BIP143_PRIVATE_KEY)).unwrap();
    assert_eq!(hex::encode(signer.public_key), BIP143_PUBLIC_KEY);
    assert_eq!(hex::encode(signer.script_pubkey()), BIP143_SCRIPT_PUBKEY);

    let sighash = tx
        .p2wpkh_sighash_all(1, &signer.pubkey_hash, BIP143_AMOUNT)
        .unwrap();
    assert_eq!(hex::encode(sighash), BIP143_SIGHASH);

    // RFC 6979 reproduces the signature published in BIP-143.
    let signature = signer.sign_sighash_all(&sighash).unwrap();
    assert_eq!(hex::encode(&signature), BIP143_SIGNATURE);
    verify(&signer, &sighash, &signature);
}

/// Assert `signature` is a low-S SIGHASH_ALL ECDSA signature over `sighash`.
pub(super) fn verify(signer: &P2wpkhSigner, sighash: &[u8; 32], signature: &[u8]) {
    let (sighash_type, der) = signature.split_last().unwrap();
    assert_eq!(*sighash_type, 0x01);
    let signature = Signature::from_der(der).unwrap();
    assert_eq!(
        signature.normalize_s(),
        signature,
        "signature must be low-S"
    );
    VerifyingKey::from_sec1_bytes(&signer.public_key)
        .unwrap()
        .verify_prehash(sighash, &signature)
        .unwrap();
}

#[test]
fn bip322_message_hash_and_virtual_transaction_vectors() {
    // bip-0322/basic-test-vectors.json, "tx_hashes".
    let cases: [(&str, &str, &str, &str); 3] = [
        (
            "",
            "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1",
            "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7",
            "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6",
        ),
        (
            "Hello World",
            "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a",
            "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b",
            "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf",
        ),
        (
            "UTF-8 support: \u{f6}\u{e4}\u{fc}\u{e9}\u{e0}\u{e8} \u{6d4b}\u{8bd5}\u{6587}\u{672c} \u{1f604}",
            "43936b237ea38c7794eb5d755e0d220b6db92ebfc5c8f482759d22b1286376d7",
            "c8f4f525fe8afb1bc09b44175bd2096f079c98425e8a1be676b712add1fb62f0",
            "8f488e06b89eafd019ec528109eafaf7f1d1811fd617aa1eeb9658f1c1be6586",
        ),
    ];
    // The vectors' key, L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k.
    let signer = P2wpkhSigner::new(&key(BIP322_PRIVATE_KEY)).unwrap();
    assert_eq!(
        signer.address(),
        "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
    );
    let challenge = signer.script_pubkey();

    for (message, expected_hash, expected_to_spend, expected_to_sign) in cases {
        assert_eq!(hex::encode(message_hash(message.as_bytes())), expected_hash);
        let to_spend = to_spend(&challenge, message.as_bytes());
        assert_eq!(display_txid(to_spend.txid()), expected_to_spend);
        assert_eq!(
            display_txid(to_sign(to_spend.txid()).txid()),
            expected_to_sign
        );
    }
}

#[test]
fn keypair_debug_redacts_private_key() {
    let keypair = derive_bitcoin_p2wpkh_keypair(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        0,
        0,
        0,
        None,
    )
    .unwrap();
    let debug = format!("{keypair:?}");
    assert!(debug.contains("private_key: \"***\""));
    assert!(!debug.contains(&hex::encode(keypair.private_key)));
}

#[test]
fn compact_size_must_be_minimal() {
    assert_eq!(Reader::new(&[0xfc]).compact_size().unwrap(), 0xfc);
    assert_eq!(
        Reader::new(&[0xfd, 0xfd, 0x00]).compact_size().unwrap(),
        0xfd
    );
    for non_minimal in [
        &[0xfd, 0xfc, 0x00][..],
        &[0xfe, 0xff, 0xff, 0x00, 0x00][..],
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00][..],
    ] {
        assert!(matches!(
            Reader::new(non_minimal).compact_size(),
            Err(KmsError::DeserializationError(_))
        ));
    }
}

#[test]
fn transaction_parsers_fail_closed() {
    let legacy = bytes(BIP143_UNSIGNED_TX);
    let mut trailing = legacy.clone();
    trailing.push(0);
    let truncated = &legacy[..legacy.len() - 1];
    let mut no_outputs = legacy[..legacy.len() - 4].to_vec();
    no_outputs.truncate(4 + 1 + 2 * 41);
    no_outputs.extend([0x00, 0, 0, 0, 0]);

    for invalid in [&trailing[..], truncated, &no_outputs[..], &[0u8; 4][..]] {
        assert!(Transaction::parse_legacy(invalid).is_err());
        assert!(Transaction::parse_network(invalid).is_err());
    }
}

#[test]
fn network_parser_reads_segwit_and_ignores_witness_for_txid() {
    // BIP-143's signed form of the same transaction.
    let signed = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
    let tx = Transaction::parse_network(&bytes(signed)).unwrap();
    let unsigned = Transaction::parse_legacy(&bytes(BIP143_UNSIGNED_TX)).unwrap();
    assert_eq!(tx.outputs, unsigned.outputs);
    assert_eq!(tx.inputs[1], unsigned.inputs[1]);
    // The witness-serialized form is not a valid legacy serialization.
    assert!(Transaction::parse_legacy(&bytes(signed)).is_err());
}
