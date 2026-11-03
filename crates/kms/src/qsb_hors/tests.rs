//! Key-level checks against the BIP's `vectors.json`, copied verbatim into
//! `tests/fixtures/qsb_hors_v1_vectors.json`. `K` has no public path out of
//! this module, so the vectors stated in terms of `K` are checked here.

use super::key::{hash160, hmac, slip21_child_key, QsbKey};
use super::*;
use crate::mnemonic::mnemonic_to_seed;
use serde::Deserialize;
use zeroize::Zeroizing;

const VECTORS: &str = include_str!("../../tests/fixtures/qsb_hors_v1_vectors.json");

#[derive(Deserialize)]
struct Vectors {
    seed_vectors: Vec<SeedVector>,
    key: String,
    secrets: Vec<SecretVector>,
    roots: Vec<RootVector>,
    disclosure: DisclosureVector,
    binding_encoding: BindingVector,
}

#[derive(Deserialize)]
struct SeedVector {
    seed_source: String,
    mnemonic: Option<String>,
    passphrase: Option<String>,
    seed: String,
    key: String,
}

#[derive(Deserialize)]
struct SecretVector {
    net: u8,
    v: u32,
    r: u8,
    i: u16,
    secret: String,
    commitment: String,
}

#[derive(Deserialize)]
struct RootVector {
    net: u8,
    v: u32,
    root: String,
}

#[derive(Deserialize)]
struct DisclosureVector {
    round0: Vec<u16>,
    round1: Vec<u16>,
    binding: String,
    digest: String,
}

#[derive(Deserialize)]
struct BindingVector {
    transaction: String,
    binding: String,
    round0: Vec<u16>,
    round1: Vec<u16>,
    digest: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS).expect("BIP vectors parse")
}

fn bytes(value: &str) -> Vec<u8> {
    hex::decode(value).expect("vector hex")
}

fn key_from_hex(value: &str) -> QsbKey {
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes(value));
    QsbKey(key)
}

fn vault(net: u8, index: u32) -> QsbVault {
    QsbVault::new(net, index).expect("valid vault")
}

#[test]
fn slip21_matches_the_slip_0021_vector() {
    let seed = mnemonic_to_seed(&["all"; 12].join(" "), "").unwrap();
    assert_eq!(
        hex::encode(slip21_child_key(&seed, b"SLIP-0021").unwrap().as_ref()),
        "1d065e3ac1bbe5c7fad32cf2305f7d709dc070d672044a19e610c77cdf33de0d",
    );
}

#[test]
fn seed_vectors_give_k() {
    for vector in vectors().seed_vectors {
        let seed = bytes(&vector.seed);
        let key = QsbKey::from_seed(&seed).unwrap();
        assert_eq!(
            hex::encode(key.0.as_ref()),
            vector.key,
            "{}",
            vector.seed_source
        );
        if vector.seed_source == "bip39" {
            let mnemonic = vector.mnemonic.as_deref().expect("bip39 mnemonic");
            let passphrase = vector.passphrase.as_deref().expect("bip39 passphrase");
            assert_eq!(
                &mnemonic_to_seed(mnemonic, passphrase).unwrap()[..],
                &seed[..]
            );
            let key = QsbKey::from_mnemonic(mnemonic, Some(passphrase)).unwrap();
            assert_eq!(hex::encode(key.0.as_ref()), vector.key);
        }
    }
}

#[test]
fn secret_vectors_cover_both_namespaces_and_index_boundaries() {
    let vectors = vectors();
    let key = key_from_hex(&vectors.key);
    for vector in vectors.secrets {
        let vault = vault(vector.net, vector.v);
        let secret = key.secret(vault, vector.r, vector.i).unwrap();
        assert_eq!(hex::encode(secret.as_ref()), vector.secret);
        assert_eq!(hex::encode(hash160(secret.as_ref())), vector.commitment);

        let commitments = key.commitments(vault).unwrap();
        let round = [&commitments.round0, &commitments.round1][usize::from(vector.r)];
        assert_eq!(hex::encode(round[usize::from(vector.i)]), vector.commitment);
    }
}

#[test]
fn root_vectors_separate_vaults_and_namespaces() {
    let vectors = vectors();
    let key = key_from_hex(&vectors.key);
    for vector in &vectors.roots {
        let commitments = key.commitments(vault(vector.net, vector.v)).unwrap();
        assert_eq!(hex::encode(commitments.root), vector.root);
    }
    assert_ne!(vectors.roots[0].root, vectors.roots[2].root);
}

#[test]
fn disclosure_vector_encodes_indices_and_binding() {
    let vector = vectors().disclosure;
    let indices = QsbRevealIndices::new(&vector.round0, &vector.round1).unwrap();
    let binding: [u8; 32] = bytes(&vector.binding).try_into().unwrap();
    assert_eq!(
        hex::encode(reveal_digest(&indices, &binding)),
        vector.digest
    );

    let mut reversed = vector.round0.clone();
    reversed.reverse();
    let reversed = QsbRevealIndices::new(&reversed, &vector.round1).unwrap();
    assert_ne!(
        hex::encode(reveal_digest(&reversed, &binding)),
        vector.digest
    );
}

#[test]
fn binding_vector_is_derived_from_the_serialized_transaction() {
    let vector = vectors().binding_encoding;
    let indices = QsbRevealIndices::new(&vector.round0, &vector.round1).unwrap();
    let digest = qsb_reveal_digest(&bytes(&vector.transaction), &indices).unwrap();
    assert_eq!(hex::encode(digest.binding), vector.binding);
    assert_eq!(hex::encode(digest.digest), vector.digest);
    assert_eq!(digest.digest, reveal_digest(&indices, &digest.binding));
}

#[test]
fn preimages_are_the_requested_secrets_in_request_order() {
    let key = key_from_hex(&vectors().key);
    let vault = vault(0, 7);
    let round0 = [3, 149, 0, 7, 6, 5, 4, 2];
    let round1 = [3, 0, 149, 140, 1, 2, 9];
    let indices = QsbRevealIndices::new(&round0, &round1).unwrap();
    let revealed = key.preimages(vault, &indices).unwrap();

    let expected = round0
        .iter()
        .map(|&index| (0, index))
        .chain(round1.iter().map(|&index| (1, index)));
    for (preimage, (round, index)) in revealed.as_array().iter().zip(expected) {
        assert_eq!(preimage, key.secret(vault, round, index).unwrap().as_ref());
    }
    // Round 0 index 3 of vault 7 is the BIP's third secret vector.
    assert_eq!(
        hex::encode(revealed.as_array()[0]),
        "47ddd932d497ec0a108ed395d9cb35830f1a984e"
    );
}

#[test]
fn preimages_wipe_on_drop_and_redact_debug() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<QsbPreimages>();

    let key = key_from_hex(&vectors().key);
    let indices = QsbRevealIndices::new(&[0, 1, 2, 3, 4, 5, 6, 7], &[0, 1, 2, 3, 4, 5, 6]).unwrap();
    let mut revealed = key.preimages(vault(0, 0), &indices).unwrap();
    assert_eq!(format!("{revealed:?}"), "QsbPreimages(***)");
    revealed.zeroize();
    assert!(revealed.as_array().iter().flatten().all(|&byte| byte == 0));
}

#[test]
fn hmac_matches_rfc_4231() {
    let message: &[&[u8]] = &[b"what do ya ", b"want for nothing?"];
    assert_eq!(
        hex::encode(hmac::<Sha256, 32>(b"Jefe", message).unwrap().as_ref()),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    );
    assert_eq!(
        hex::encode(hmac::<sha2::Sha512, 64>(b"Jefe", message).unwrap().as_ref()),
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    );
}

#[test]
fn hmac_matches_the_hmac_crate_up_to_one_block() {
    use ::hmac::{Hmac, KeyInit, Mac};
    let key: Vec<u8> = (0..=255u8).collect();
    let message = b"QSB-HORS-v1 differential message";
    for len in [0, 1, 20, 32, 63, 64] {
        let mut expected = Hmac::<Sha256>::new_from_slice(&key[..len]).unwrap();
        expected.update(message);
        let actual = hmac::<Sha256, 32>(&key[..len], &[message]).unwrap();
        assert_eq!(&actual[..], &expected.finalize().into_bytes()[..], "{len}");
    }
    for len in [0, 18, 32, 64, 127, 128] {
        let mut expected = Hmac::<sha2::Sha512>::new_from_slice(&key[..len]).unwrap();
        expected.update(message);
        let actual = hmac::<sha2::Sha512, 64>(&key[..len], &[message]).unwrap();
        assert_eq!(&actual[..], &expected.finalize().into_bytes()[..], "{len}");
    }
}

#[test]
fn hmac_refuses_keys_longer_than_a_block_and_wrong_output_sizes() {
    assert!(hmac::<Sha256, 32>(&[0xaa; 65], &[b"x"]).is_err());
    assert!(hmac::<sha2::Sha512, 64>(&[0xaa; 129], &[b"x"]).is_err());
    assert!(hmac::<Sha256, 64>(b"key", &[b"x"]).is_err());
}

#[test]
fn hash_states_wipe_themselves_on_drop() {
    // Fails to compile if sha2's `zeroize` feature is dropped.
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<Sha256>();
    assert_zeroize_on_drop::<sha2::Sha512>();
}
