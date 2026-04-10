//! Starknet account contract address derivation.
//!
//! This module provides utilities for deriving Starknet account contract addresses
//! following the standard contract address calculation formula.

use krusty_kms_common::{KmsError, Result};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};

/// Starknet contract address prefix for address calculation.
const CONTRACT_ADDRESS_PREFIX: &str = "STARKNET_CONTRACT_ADDRESS";

/// Calculate a Starknet contract address from its deployment parameters.
///
/// This implements the standard contract address calculation using `computeHashOnElements`:
/// ```text
/// calldata_hash = computeHashOnElements(constructor_calldata)
/// address = computeHashOnElements([
///     "STARKNET_CONTRACT_ADDRESS",
///     deployer_address,
///     salt,
///     class_hash,
///     calldata_hash
/// ])
/// ```
///
/// # Arguments
/// * `salt` - Salt value for address derivation (typically 0 for standard accounts)
/// * `class_hash` - The class hash of the account contract (e.g., `OpenZeppelin` account)
/// * `constructor_calldata` - The calldata passed to the constructor
/// * `deployer_address` - Address of the deployer (0 for counterfactual deployment)
///
/// # Returns
/// The calculated contract address as a `Felt`.
///
/// # Errors
///
/// Returns [`KmsError`] if:
/// - Short string encoding fails (> 31 characters) (`CryptoError`)
///
/// # Cyclomatic Complexity: 1
pub fn calculate_contract_address(
    salt: &Felt,
    class_hash: &Felt,
    constructor_calldata: &[Felt],
    deployer_address: &Felt,
) -> Result<Felt> {
    // Calculate the hash of constructor calldata
    let calldata_hash = hash_elements(constructor_calldata);

    // Encode the prefix string as a Cairo short string (not keccak!)
    // This matches the Swift/TypeScript implementation
    let prefix_felt = encode_short_string(CONTRACT_ADDRESS_PREFIX)?;

    // Calculate address using computeHashOnElements on the array
    // [PREFIX, deployer, salt, class_hash, calldata_hash]
    let elements = vec![
        prefix_felt,
        *deployer_address,
        *salt,
        *class_hash,
        calldata_hash,
    ];
    let address = hash_elements(&elements);

    Ok(address)
}

/// Hash an array of Felts using the Starknet `computeHashOnElements` algorithm.
///
/// This implements the standard Pedersen hashing for arrays:
/// ```text
/// 1. Chain hash: hash_chain = pedersen(pedersen(...pedersen(0, arr[0]), arr[1]), arr[2])
/// 2. Final hash: hash = pedersen(hash_chain, array_length)
/// ```
///
/// This is equivalent to starknet.js's `computeHashOnElements` / `computePedersenHashOnElements`.
///
/// # Cyclomatic Complexity: 1
pub fn hash_elements(elements: &[Felt]) -> Felt {
    // Step 1: Chain hash all elements starting from 0
    let mut current = Felt::ZERO;
    for element in elements {
        current = Pedersen::hash(&current, element);
    }

    // Step 2: Hash with array length
    let length = Felt::from(elements.len() as u64);
    Pedersen::hash(&current, &length)
}

/// Encode a string as a Cairo short string.
///
/// Cairo short strings are encoded by converting the ASCII bytes directly to a big integer.
/// This matches the `Felt.fromShortString()` in Swift and `shortString.encodeShortString()` in TypeScript.
///
/// # Arguments
/// * `s` - The string to encode (must be <= 31 characters for a single Felt)
///
/// # Cyclomatic Complexity: 1
pub fn encode_short_string(s: &str) -> Result<Felt> {
    let bytes = s.as_bytes();
    if bytes.len() > 31 {
        return Err(KmsError::CryptoError(
            "Short string must be <= 31 characters".to_string(),
        ));
    }

    // Convert bytes directly to a Felt (big-endian)
    Ok(Felt::from_bytes_be_slice(bytes))
}

/// Derive an `OpenZeppelin` account contract address from a public key.
///
/// This is a convenience function for the standard `OpenZeppelin` account
/// pattern where the constructor takes a single `public_key` parameter.
///
/// # Arguments
/// * `public_key` - The Stark public key (compressed, x-coordinate only)
/// * `class_hash` - The `OpenZeppelin` account class hash
/// * `salt` - Optional salt (defaults to 0)
///
/// # Returns
/// The derived account contract address.
///
/// # Errors
///
/// Returns [`KmsError`] if:
/// - Public key point is at infinity (`CryptoError`)
/// - Short string encoding fails (`CryptoError`)
///
/// # Cyclomatic Complexity: 1
pub fn derive_oz_account_address(
    public_key: &Felt,
    class_hash: &Felt,
    salt: Option<&Felt>,
) -> Result<Felt> {
    let salt = salt.unwrap_or(&Felt::ZERO);

    // OpenZeppelin account constructor takes [public_key]
    let constructor_calldata = vec![*public_key];

    // Deployer address is 0 for counterfactual deployment
    let deployer_address = Felt::ZERO;

    calculate_contract_address(salt, class_hash, &constructor_calldata, &deployer_address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_elements_empty() {
        let elements: Vec<Felt> = vec![];
        let hash = hash_elements(&elements);
        // Empty array: pedersen(0, 0)
        let expected = Pedersen::hash(&Felt::ZERO, &Felt::ZERO);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hash_elements_single() {
        let elements = vec![Felt::from(42u64)];
        let hash = hash_elements(&elements);
        assert_ne!(hash, Felt::ZERO);
    }

    #[test]
    fn test_calculate_contract_address() {
        let salt = Felt::ZERO;
        let class_hash = Felt::from(123456u64);
        let public_key = Felt::from(789u64);
        let constructor_calldata = vec![public_key];
        let deployer = Felt::ZERO;

        let address =
            calculate_contract_address(&salt, &class_hash, &constructor_calldata, &deployer);
        assert!(address.is_ok());

        let addr = address.unwrap();
        assert_ne!(addr, Felt::ZERO);
    }

    #[test]
    fn test_derive_oz_account_address() {
        let public_key = Felt::from(0x1234567890abcdefu64);
        let class_hash = Felt::from(0xabcdef123456u64);

        let address = derive_oz_account_address(&public_key, &class_hash, None);
        assert!(address.is_ok());
    }

    #[test]
    fn test_deterministic_address_derivation() {
        let public_key = Felt::from(42u64);
        let class_hash = Felt::from(123u64);

        let addr1 = derive_oz_account_address(&public_key, &class_hash, None).unwrap();
        let addr2 = derive_oz_account_address(&public_key, &class_hash, None).unwrap();

        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_different_public_keys_produce_different_addresses() {
        let class_hash = Felt::from(123u64);

        let addr1 = derive_oz_account_address(&Felt::from(1u64), &class_hash, None).unwrap();
        let addr2 = derive_oz_account_address(&Felt::from(2u64), &class_hash, None).unwrap();

        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_short_string_too_long() {
        // Short strings must be <= 31 characters
        let long_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"; // 32 chars
        let result = encode_short_string(long_string);
        assert!(result.is_err());
        if let Err(KmsError::CryptoError(msg)) = result {
            assert!(msg.contains("31 characters"));
        }
    }

    #[test]
    fn test_encode_short_string_valid() {
        let result = encode_short_string("hello");
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_oz_account_with_custom_salt() {
        let public_key = Felt::from(0x1234567890abcdefu64);
        let class_hash = Felt::from(0xabcdef123456u64);
        let salt = Felt::from(42u64);

        let addr_with_salt =
            derive_oz_account_address(&public_key, &class_hash, Some(&salt)).unwrap();
        let addr_without_salt = derive_oz_account_address(&public_key, &class_hash, None).unwrap();

        assert_ne!(addr_with_salt, addr_without_salt);
    }

    #[test]
    fn test_hash_elements_multiple() {
        let elements = vec![Felt::from(1u64), Felt::from(2u64), Felt::from(3u64)];
        let hash = hash_elements(&elements);
        assert_ne!(hash, Felt::ZERO);
    }
}
