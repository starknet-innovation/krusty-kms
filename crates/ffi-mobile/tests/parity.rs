//! Cross-implementation vector: the address this crate derives must be the
//! address the wallet derives, or the phone shows one account while the wallet
//! funds another.
//!
//! The public key is `tasks/keys/key.json` from the ml-dsa-cairo repository —
//! the same fixture the Cairo side uses, public half only. The expected address
//! was produced by **starknet.js**, independently of this code:
//!
//! ```js
//! hash.calculateContractAddressFromHash("0x0", CLASS_HASH, [COMMITMENT], 0)
//! ```
//!
//! which is verbatim what `mlDsaAccountAddress` in mc-wallet calls.

use kms_mobile::{account_address, key_commitment, ML_DSA_65_PUBLIC_KEY_BYTES};

/// Compiled from `account_hashkey/` in the contract repository, and what the
/// wallet has been tested against.
const CLASS_HASH: &str = "0x430e051d9ed7ca553ed4b8dc7e8cfc16400d13fc9b0d4279206687c2059356f";

/// `ML_DSA_ADDRESS_SALT` in mc-wallet.
const SALT: &str = "0x0";

const EXPECTED_COMMITMENT: &str =
    "0x031864350faa9b8f9e1fcdafdf30a45d41d4e77965929d9eace35485a3931fc6";

/// starknet.js printed `0x4f77...` — 63 digits. This ABI always pads to 64, so
/// a caller cannot receive a shorter spelling of the same felt; the leading zero
/// here is that guarantee, not a typo.
const EXPECTED_ADDRESS: &str = "0x04f77639f2f9fa6c720b4100bb3357938274060e693e7e030a939d19f660f9bf";

fn fixture_public_key() -> Vec<u8> {
    let hex_str = include_str!("testdata/ml_dsa_65_public_key.hex").trim();
    let key = hex::decode(hex_str).expect("fixture is valid hex");
    assert_eq!(key.len(), ML_DSA_65_PUBLIC_KEY_BYTES);
    key
}

#[test]
fn commitment_matches_the_pinned_vector() {
    assert_eq!(
        key_commitment(&fixture_public_key()).unwrap(),
        EXPECTED_COMMITMENT
    );
}

#[test]
fn address_matches_starknet_js() {
    assert_eq!(
        account_address(&fixture_public_key(), CLASS_HASH, SALT).unwrap(),
        EXPECTED_ADDRESS,
    );
}

#[test]
fn a_different_salt_gives_a_different_address() {
    // Guards the salt actually reaching the derivation: a parameter that is
    // accepted and ignored would pass the test above and be wrong everywhere.
    let key = fixture_public_key();
    assert_ne!(
        account_address(&key, CLASS_HASH, SALT).unwrap(),
        account_address(&key, CLASS_HASH, "0x1").unwrap(),
    );
}

#[test]
fn a_different_class_hash_gives_a_different_address() {
    let key = fixture_public_key();
    assert_ne!(
        account_address(&key, CLASS_HASH, SALT).unwrap(),
        account_address(&key, "0x1", SALT).unwrap(),
    );
}
