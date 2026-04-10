use krusty_kms::{
    derive_keypair_with_coin_type, derive_nostr_keypair, derive_oz_account_address,
    derive_private_key_with_coin_type, mnemonic_to_seed, nostr_public_key, sign_nostr_event_id,
    sign_stark_hash, stark_public_key,
};
use serde::Deserialize;
use starknet_crypto::Felt as StarkSignatureFelt;
use starknet_types_core::felt::Felt;

#[derive(Debug, Deserialize)]
struct MnemonicSeedFile {
    vectors: Vec<MnemonicSeedVector>,
}

#[derive(Debug, Deserialize)]
struct MnemonicSeedVector {
    mnemonic: String,
    passphrase: String,
    seed_hex: String,
}

#[derive(Debug, Deserialize)]
struct CoinDerivationFile {
    mnemonic: String,
    passphrase: String,
    vectors: Vec<CoinDerivationVector>,
}

#[derive(Debug, Deserialize)]
struct CoinDerivationVector {
    coin_type: u32,
    index: u32,
    account_index: u32,
    expected_private_key: String,
}

#[derive(Debug, Deserialize)]
struct NostrDerivationFile {
    vectors: Vec<NostrDerivationVector>,
}

#[derive(Debug, Deserialize)]
struct NostrDerivationVector {
    mnemonic: String,
    coin_type: u32,
    index: u32,
    account_index: u32,
    expected_private_key_hex: String,
    expected_public_key_xonly_hex: String,
}

#[derive(Debug, Deserialize)]
struct AccountAddressFile {
    vectors: Vec<AccountAddressVector>,
}

#[derive(Debug, Deserialize)]
struct AccountAddressVector {
    mnemonic: String,
    coin_type: u32,
    index: u32,
    account_index: u32,
    class_hash: String,
    salt: String,
    expected_public_key_x: String,
    expected_address: String,
}

#[derive(Debug, Deserialize)]
struct StarkSigningFile {
    vectors: Vec<StarkSigningVector>,
}

#[derive(Debug, Deserialize)]
struct StarkSigningVector {
    private_key: String,
    message_hash: String,
    expected_public_key: String,
    expected_r: String,
    expected_s: String,
}

#[derive(Debug, Deserialize)]
struct NostrSigningFile {
    vectors: Vec<NostrSigningVector>,
}

#[derive(Debug, Deserialize)]
struct NostrSigningVector {
    private_key_hex: String,
    event_id_hex: String,
    expected_public_key_hex: String,
    expected_signature_hex: String,
}

fn read_fixture<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let content = match name {
        "mnemonic_seed_vectors.json" => include_str!("fixtures/mnemonic_seed_vectors.json"),
        "coin_derivation_vectors.json" => include_str!("fixtures/coin_derivation_vectors.json"),
        "nostr_derivation_vectors.json" => include_str!("fixtures/nostr_derivation_vectors.json"),
        "account_address_vectors.json" => include_str!("fixtures/account_address_vectors.json"),
        "stark_signing_vectors.json" => include_str!("fixtures/stark_signing_vectors.json"),
        "nostr_signing_vectors.json" => include_str!("fixtures/nostr_signing_vectors.json"),
        _ => panic!("unknown release fixture: {name}"),
    };

    serde_json::from_str(content).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn decode_array<const N: usize>(value: &str) -> [u8; N] {
    let bytes = hex::decode(value).unwrap();
    bytes.try_into().unwrap()
}

#[test]
fn mnemonic_seed_release_vectors_match() {
    let file: MnemonicSeedFile = read_fixture("mnemonic_seed_vectors.json");

    for vector in file.vectors {
        let seed = mnemonic_to_seed(&vector.mnemonic, &vector.passphrase).unwrap();
        assert_eq!(hex::encode(seed), vector.seed_hex, "{}", vector.mnemonic);
    }
}

#[test]
fn coin_derivation_release_vectors_match() {
    let file: CoinDerivationFile = read_fixture("coin_derivation_vectors.json");

    for vector in file.vectors {
        let derived = derive_private_key_with_coin_type(
            &file.mnemonic,
            vector.index,
            vector.account_index,
            vector.coin_type,
            Some(&file.passphrase),
        )
        .unwrap();

        assert_eq!(
            derived,
            Felt::from_hex(&vector.expected_private_key).unwrap(),
            "coin_type={} index={} account_index={}",
            vector.coin_type,
            vector.index,
            vector.account_index
        );
    }
}

#[test]
fn nostr_derivation_release_vectors_match() {
    let file: NostrDerivationFile = read_fixture("nostr_derivation_vectors.json");

    for vector in file.vectors {
        assert_eq!(
            vector.coin_type, 1237,
            "release vectors pin Nostr to SLIP-44 1237"
        );

        let keypair =
            derive_nostr_keypair(&vector.mnemonic, vector.index, vector.account_index, None)
                .unwrap();

        assert_eq!(
            hex::encode(keypair.private_key),
            vector.expected_private_key_hex,
            "{}",
            vector.mnemonic
        );
        assert_eq!(
            hex::encode(keypair.public_key),
            vector.expected_public_key_xonly_hex,
            "{}",
            vector.mnemonic
        );
    }
}

#[test]
fn account_address_release_vectors_match() {
    let file: AccountAddressFile = read_fixture("account_address_vectors.json");

    for vector in file.vectors {
        let keypair = derive_keypair_with_coin_type(
            &vector.mnemonic,
            vector.index,
            vector.account_index,
            vector.coin_type,
            None,
        )
        .unwrap();
        let public_key_x = keypair.public_key.to_affine().unwrap().x();
        let address = derive_oz_account_address(
            &public_key_x,
            &Felt::from_hex(&vector.class_hash).unwrap(),
            Some(&Felt::from_hex(&vector.salt).unwrap()),
        )
        .unwrap();

        assert_eq!(
            public_key_x,
            Felt::from_hex(&vector.expected_public_key_x).unwrap()
        );
        assert_eq!(address, Felt::from_hex(&vector.expected_address).unwrap());
    }
}

#[test]
fn stark_signing_release_vectors_match() {
    let file: StarkSigningFile = read_fixture("stark_signing_vectors.json");

    for vector in file.vectors {
        let private_key = StarkSignatureFelt::from_hex(&vector.private_key).unwrap();
        let message_hash = StarkSignatureFelt::from_hex(&vector.message_hash).unwrap();
        let signature = sign_stark_hash(&private_key, &message_hash).unwrap();

        assert_eq!(
            stark_public_key(&private_key),
            StarkSignatureFelt::from_hex(&vector.expected_public_key).unwrap()
        );
        assert_eq!(
            signature.public_key,
            StarkSignatureFelt::from_hex(&vector.expected_public_key).unwrap()
        );
        assert_eq!(
            signature.r,
            StarkSignatureFelt::from_hex(&vector.expected_r).unwrap()
        );
        assert_eq!(
            signature.s,
            StarkSignatureFelt::from_hex(&vector.expected_s).unwrap()
        );
    }
}

#[test]
fn nostr_signing_release_vectors_match() {
    let file: NostrSigningFile = read_fixture("nostr_signing_vectors.json");

    for vector in file.vectors {
        let private_key = decode_array::<32>(&vector.private_key_hex);
        let event_id = decode_array::<32>(&vector.event_id_hex);
        let signature = sign_nostr_event_id(&private_key, &event_id).unwrap();

        assert_eq!(
            hex::encode(nostr_public_key(&private_key).unwrap()),
            vector.expected_public_key_hex
        );
        assert_eq!(
            hex::encode(signature.public_key),
            vector.expected_public_key_hex
        );
        assert_eq!(
            hex::encode(signature.signature),
            vector.expected_signature_hex
        );
    }
}
