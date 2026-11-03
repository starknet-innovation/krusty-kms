//! Official Bitcoin vectors for the public Bitcoin API: BIP-84 derivation,
//! BIP-322 simple signatures, and the BIP-174 parser cases.
//!
//! Vectors are copied from `bitcoin/bips` (see `_source` in the fixture).
//! Private keys are kept in their published WIF form and decoded here.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use krusty_kms::{
    derive_bitcoin_p2wpkh_keypair, sign_bip322_simple, sign_bitcoin_psbt_inputs, Bip322Encoding,
};
use krusty_kms_common::KmsError;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Fixture {
    bip84: Bip84,
    bip322_simple: Vec<Bip322Vector>,
    bip174_invalid: Vec<PsbtCase>,
    bip174_valid: Vec<PsbtCase>,
}

#[derive(Deserialize)]
struct Bip84 {
    mnemonic: String,
    vectors: Vec<Bip84Vector>,
}

#[derive(Deserialize)]
struct Bip84Vector {
    account: u32,
    change: u32,
    index: u32,
    path: String,
    private_key_wif: String,
    public_key: String,
    address: String,
}

#[derive(Deserialize)]
struct Bip322Vector {
    message: String,
    private_key_wif: String,
    address: String,
    signatures: Vec<String>,
}

#[derive(Deserialize)]
struct PsbtCase {
    case: String,
    psbt: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/bitcoin_vectors.json")).unwrap()
}

/// Decode a mainnet compressed-key WIF (base58check `0x80 || key || 0x01`).
fn wif_private_key(wif: &str) -> [u8; 32] {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes = [0u8; 38];
    for character in wif.bytes() {
        let mut carry = ALPHABET.iter().position(|&c| c == character).unwrap() as u32;
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        assert_eq!(carry, 0, "WIF overflows 38 bytes");
    }
    let (payload, checksum) = bytes.split_at(34);
    assert_eq!(&Sha256::digest(Sha256::digest(payload))[..4], checksum);
    assert_eq!((payload[0], payload[33]), (0x80, 0x01));
    payload[1..33].try_into().unwrap()
}

#[test]
fn bip84_vectors_derive_keys_addresses_and_paths() {
    let fixture = fixture();
    for vector in &fixture.bip84.vectors {
        let keypair = derive_bitcoin_p2wpkh_keypair(
            &fixture.bip84.mnemonic,
            vector.account,
            vector.change,
            vector.index,
            None,
        )
        .unwrap();
        assert_eq!(
            keypair.private_key,
            wif_private_key(&vector.private_key_wif)
        );
        assert_eq!(hex::encode(keypair.public_key), vector.public_key);
        assert_eq!(keypair.address, vector.address);
        assert_eq!(keypair.path, vector.path);
    }
}

#[test]
fn bip84_derivation_refuses_invalid_paths_and_mnemonics() {
    let mnemonic = fixture().bip84.mnemonic;
    let invalid_paths = [(0x8000_0000, 0, 0), (0, 2, 0), (0, 0, 0x8000_0000)];
    for (account, change, index) in invalid_paths {
        assert!(matches!(
            derive_bitcoin_p2wpkh_keypair(&mnemonic, account, change, index, None),
            Err(KmsError::InvalidDerivationPath(_))
        ));
    }
    let bad_checksum = mnemonic.replace("about", "abandon");
    assert!(matches!(
        derive_bitcoin_p2wpkh_keypair(&bad_checksum, 0, 0, 0, None),
        Err(KmsError::InvalidMnemonic(_))
    ));

    let with_passphrase = derive_bitcoin_p2wpkh_keypair(&mnemonic, 0, 0, 0, Some("qsb")).unwrap();
    let without = derive_bitcoin_p2wpkh_keypair(&mnemonic, 0, 0, 0, None).unwrap();
    assert_ne!(with_passphrase.address, without.address);
}

#[test]
fn bip322_simple_vectors_reproduce_the_published_signature() {
    for vector in fixture().bip322_simple {
        let key = wif_private_key(&vector.private_key_wif);
        let message = vector.message.as_bytes();
        let sign = |address: &str, encoding| sign_bip322_simple(&key, address, message, encoding);
        // Each vector lists the low-R signature Bitcoin Core's grinding
        // produces, which this signer matches, and the plain RFC 6979 one,
        // whose r needs a DER padding byte.
        let witness_len = |encoded: &str| BASE64.decode(&encoded[3..]).unwrap().len();
        assert_eq!(
            witness_len(&vector.signatures[1]),
            witness_len(&vector.signatures[0]) + 1
        );

        // The default is the conformant `smp`-prefixed form, byte for byte.
        let prefixed = sign(&vector.address, Bip322Encoding::default()).unwrap();
        assert_eq!(
            prefixed, vector.signatures[0],
            "message {:?}",
            vector.message
        );
        // The legacy opt-in is the same witness without the prefix.
        let legacy = sign(&vector.address, Bip322Encoding::LegacyUnprefixed).unwrap();
        assert_eq!(Some(legacy.as_str()), prefixed.strip_prefix("smp"));

        let upper = vector.address.to_ascii_uppercase();
        assert_eq!(sign(&upper, Bip322Encoding::Prefixed).unwrap(), prefixed);
    }
}

#[test]
fn bip322_refuses_an_address_that_is_not_the_keys() {
    let fixture = fixture();
    let vector = &fixture.bip322_simple[0];
    let key = wif_private_key(&vector.private_key_wif);
    let mut mixed_case = vector.address.clone();
    mixed_case.replace_range(0..2, "BC");
    let other_key_address = &fixture.bip84.vectors[0].address;
    let nested_segwit = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

    for address in [other_key_address.as_str(), &mixed_case, nested_segwit, ""] {
        assert!(matches!(
            sign_bip322_simple(&key, address, b"Hello World", Bip322Encoding::Prefixed),
            Err(KmsError::CryptoError(_))
        ));
    }
    assert!(matches!(
        sign_bip322_simple(&[0u8; 32], &vector.address, b"", Bip322Encoding::Prefixed),
        Err(KmsError::InvalidPrivateKey(_))
    ));
}

#[test]
fn bip174_invalid_psbts_are_refused_as_malformed() {
    let key = wif_private_key(&fixture().bip322_simple[0].private_key_wif);
    for case in fixture().bip174_invalid {
        let result = sign_bitcoin_psbt_inputs(&key, &case.psbt, &[0]);
        assert!(
            matches!(result, Err(KmsError::DeserializationError(_))),
            "{}: {result:?}",
            case.case
        );
    }
}

#[test]
fn bip174_valid_psbts_parse_but_have_nothing_for_this_key() {
    let key = wif_private_key(&fixture().bip322_simple[0].private_key_wif);
    for case in fixture().bip174_valid {
        let result = sign_bitcoin_psbt_inputs(&key, &case.psbt, &[0]);
        assert!(
            matches!(result, Err(KmsError::TransactionError(_))),
            "{}: {result:?}",
            case.case
        );
    }
}
