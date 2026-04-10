use krusty_kms::{
    hash_elements, AccountClass, ArgentAccount, BraavosAccount, OpenZeppelinAccount, SaltPolicy,
};
use serde::Deserialize;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, Poseidon, StarkHash};

// ---------------------------------------------------------------------------
// Fixture types – hashing_vectors.json
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct HashingFile {
    vectors: HashingVectors,
}

#[derive(Debug, Deserialize)]
struct HashingVectors {
    pedersen: Vec<PedersenVector>,
    pedersen_many: Vec<PedersenManyVector>,
    poseidon: Vec<PoseidonVector>,
    poseidon_many: Vec<PoseidonManyVector>,
    starknet_keccak: Vec<KeccakVector>,
}

#[derive(Debug, Deserialize)]
struct PedersenVector {
    name: String,
    a: String,
    b: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct PedersenManyVector {
    name: String,
    inputs: Vec<String>,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct PoseidonVector {
    name: String,
    a: String,
    b: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct PoseidonManyVector {
    name: String,
    inputs: Vec<String>,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct KeccakVector {
    name: String,
    input: String,
    encoding: String,
    expected: String,
}

// ---------------------------------------------------------------------------
// Fixture types – account_class_vectors.json
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AccountClassFile {
    mnemonic: String,
    derivation_path: String,
    public_key: String,
    vectors: Vec<AccountClassVector>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AccountClassVector {
    name: String,
    account_type: String,
    class_hash: String,
    constructor_calldata: Vec<String>,
    salt: String,
    expected_address: String,
}

// ---------------------------------------------------------------------------
// Fixture loader
// ---------------------------------------------------------------------------

fn read_fixture<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let content = match name {
        "hashing_vectors.json" => include_str!("fixtures/hashing_vectors.json"),
        "account_class_vectors.json" => include_str!("fixtures/account_class_vectors.json"),
        _ => panic!("unknown wasm binding fixture: {name}"),
    };

    serde_json::from_str(content).unwrap_or_else(|error| panic!("{name}: {error}"))
}

/// Helper: compute starknet_keccak on a UTF-8 string.
fn starknet_keccak(input: &str) -> Felt {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    // Mask the top 6 bits so the result fits in a StarkNet felt (< 2^250).
    bytes[0] &= 0x03;
    Felt::from_bytes_be_slice(&bytes)
}

// ---------------------------------------------------------------------------
// Generator – run with --ignored to print expected values
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn generate_wasm_binding_vectors() {
    // ---- Hashing vectors ----
    let a = Felt::from_hex("0x1").unwrap();
    let b = Felt::from_hex("0x2").unwrap();

    let pedersen_two = Pedersen::hash(&a, &b);
    println!("pedersen(0x1, 0x2) = {:#x}", pedersen_two);

    let he_three = hash_elements(&[
        Felt::from_hex("0x1").unwrap(),
        Felt::from_hex("0x2").unwrap(),
        Felt::from_hex("0x3").unwrap(),
    ]);
    println!("hash_elements([0x1, 0x2, 0x3]) = {:#x}", he_three);

    let he_empty = hash_elements(&[]);
    println!("hash_elements([]) = {:#x}", he_empty);

    let poseidon_two = Poseidon::hash(&a, &b);
    println!("poseidon(0x1, 0x2) = {:#x}", poseidon_two);

    let poseidon_three = Poseidon::hash_array(&[
        Felt::from_hex("0x1").unwrap(),
        Felt::from_hex("0x2").unwrap(),
        Felt::from_hex("0x3").unwrap(),
    ]);
    println!(
        "poseidon_hash_array([0x1, 0x2, 0x3]) = {:#x}",
        poseidon_three
    );

    let keccak_transfer = starknet_keccak("transfer");
    println!("starknet_keccak(\"transfer\") = {:#x}", keccak_transfer);

    // ---- Account class vectors ----
    let pk = Felt::from_hex("0x426212993d56613e1886a4cbc5b58810570023581c2aab0b423277776b79d2e")
        .unwrap();

    let argent = ArgentAccount::new();
    let argent_addr = argent
        .calculate_address(&pk, SaltPolicy::PublicKey)
        .unwrap();
    println!("argent address = {:#x}", argent_addr);

    let braavos = BraavosAccount::new();
    let braavos_addr = braavos
        .calculate_address(&pk, SaltPolicy::PublicKey)
        .unwrap();
    println!("braavos address = {:#x}", braavos_addr);

    let oz_class =
        Felt::from_hex("0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381")
            .unwrap();
    let oz = OpenZeppelinAccount::from_class_hash(oz_class);
    let oz_addr = oz.calculate_address(&pk, SaltPolicy::Zero).unwrap();
    println!("oz address = {:#x}", oz_addr);
}

// ---------------------------------------------------------------------------
// Verification tests – hashing
// ---------------------------------------------------------------------------

#[test]
fn hashing_pedersen_vectors_match() {
    let file: HashingFile = read_fixture("hashing_vectors.json");

    for v in &file.vectors.pedersen {
        let a = Felt::from_hex(&v.a).unwrap();
        let b = Felt::from_hex(&v.b).unwrap();
        let expected = Felt::from_hex(&v.expected).unwrap();
        let actual = Pedersen::hash(&a, &b);
        assert_eq!(actual, expected, "pedersen vector '{}' mismatch", v.name);
    }
}

#[test]
fn hashing_pedersen_many_vectors_match() {
    let file: HashingFile = read_fixture("hashing_vectors.json");

    for v in &file.vectors.pedersen_many {
        let inputs: Vec<Felt> = v
            .inputs
            .iter()
            .map(|s| Felt::from_hex(s).unwrap())
            .collect();
        let expected = Felt::from_hex(&v.expected).unwrap();
        let actual = hash_elements(&inputs);
        assert_eq!(
            actual, expected,
            "pedersen_many vector '{}' mismatch",
            v.name
        );
    }
}

#[test]
fn hashing_poseidon_vectors_match() {
    let file: HashingFile = read_fixture("hashing_vectors.json");

    for v in &file.vectors.poseidon {
        let a = Felt::from_hex(&v.a).unwrap();
        let b = Felt::from_hex(&v.b).unwrap();
        let expected = Felt::from_hex(&v.expected).unwrap();
        let actual = Poseidon::hash(&a, &b);
        assert_eq!(actual, expected, "poseidon vector '{}' mismatch", v.name);
    }
}

#[test]
fn hashing_poseidon_many_vectors_match() {
    let file: HashingFile = read_fixture("hashing_vectors.json");

    for v in &file.vectors.poseidon_many {
        let inputs: Vec<Felt> = v
            .inputs
            .iter()
            .map(|s| Felt::from_hex(s).unwrap())
            .collect();
        let expected = Felt::from_hex(&v.expected).unwrap();
        let actual = Poseidon::hash_array(&inputs);
        assert_eq!(
            actual, expected,
            "poseidon_many vector '{}' mismatch",
            v.name
        );
    }
}

#[test]
fn hashing_starknet_keccak_vectors_match() {
    let file: HashingFile = read_fixture("hashing_vectors.json");

    for v in &file.vectors.starknet_keccak {
        assert_eq!(v.encoding, "utf8", "only utf8 encoding supported");
        let expected = Felt::from_hex(&v.expected).unwrap();
        let actual = starknet_keccak(&v.input);
        assert_eq!(
            actual, expected,
            "starknet_keccak vector '{}' mismatch",
            v.name
        );
    }
}

// ---------------------------------------------------------------------------
// Verification tests – account class addresses
// ---------------------------------------------------------------------------

#[test]
fn account_class_vectors_match() {
    let file: AccountClassFile = read_fixture("account_class_vectors.json");
    let pk = Felt::from_hex(&file.public_key).unwrap();

    for v in &file.vectors {
        let expected = Felt::from_hex(&v.expected_address).unwrap();

        let actual = match v.account_type.as_str() {
            "argent" => {
                let account = ArgentAccount::new();
                account
                    .calculate_address(&pk, SaltPolicy::PublicKey)
                    .unwrap()
            }
            "braavos" => {
                let account = BraavosAccount::new();
                account
                    .calculate_address(&pk, SaltPolicy::PublicKey)
                    .unwrap()
            }
            "oz" => {
                let class_hash = Felt::from_hex(&v.class_hash).unwrap();
                let oz = OpenZeppelinAccount::from_class_hash(class_hash);
                oz.calculate_address(&pk, SaltPolicy::Zero).unwrap()
            }
            other => panic!("unknown account_type: {other}"),
        };

        assert_eq!(
            actual, expected,
            "account class vector '{}' mismatch: computed {:#x}, expected {:#x}",
            v.name, actual, expected
        );
    }
}
