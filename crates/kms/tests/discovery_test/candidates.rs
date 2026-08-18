//! Discovery API tests — `generate_candidates` orchestration.

use crate::vectors::{
    ARGENT_ACCOUNT_ADDRESS, ARGENT_PRIVATE_KEY, ARGENT_PUBLIC_KEY, ARGENT_V040_CLASS_HASH,
    BRAAVOS_ACCOUNT_ADDRESS, BRAAVOS_PUBLIC_KEY, MNEMONIC,
};
use krusty_kms::{generate_candidates, WalletType};
use starknet_types_core::felt::Felt;

/// Verify that `generate_candidates` produces at least one candidate for every
/// known wallet type when scanning a single derivation index.
///
/// Expected per-index breakdown:
/// - 1 Braavos (base deployment hash)
/// - 1 Argent  (new direct derivation, v0.4.0)
/// - 3 ArgentLegacy (legacy double derivation, v0.4.0 + v0.3.1 + v0.3.0)
/// - 4 ArgentCairo0 (proxy + 4 implementation hashes)
/// - 2 OpenZeppelin (latest manifest hash, salt=pubkey + salt=0)
///
/// Total: 11 candidates per index.
#[test]
fn discovery_generates_candidates_for_all_wallet_types() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    let has_braavos = candidates
        .iter()
        .any(|c| c.wallet_type == WalletType::Braavos);
    let has_argent = candidates
        .iter()
        .any(|c| c.wallet_type == WalletType::Argent);
    let has_argent_legacy = candidates
        .iter()
        .any(|c| c.wallet_type == WalletType::ArgentLegacy);
    let has_argent_cairo0 = candidates
        .iter()
        .any(|c| c.wallet_type == WalletType::ArgentCairo0);
    let has_oz = candidates
        .iter()
        .any(|c| c.wallet_type == WalletType::OpenZeppelin);

    assert!(has_braavos, "Must have at least one Braavos candidate");
    assert!(has_argent, "Must have at least one Argent candidate");
    assert!(
        has_argent_legacy,
        "Must have at least one ArgentLegacy candidate"
    );
    assert!(
        has_argent_cairo0,
        "Must have at least one ArgentCairo0 candidate"
    );
    assert!(has_oz, "Must have at least one OpenZeppelin candidate");

    // 11 candidates per index: 1 braavos + 1 argent + 3 legacy + 4 cairo0 + 2 oz
    assert_eq!(
        candidates.len(),
        11,
        "Expected 11 candidates for 1 index, got {}",
        candidates.len()
    );
}

/// Verify that the Braavos candidate at index 0 matches the known test vector.
#[test]
fn discovery_braavos_candidate_matches_known_address() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    let braavos: Vec<_> = candidates
        .iter()
        .filter(|c| c.wallet_type == WalletType::Braavos && c.derivation_index == 0)
        .collect();

    assert_eq!(
        braavos.len(),
        1,
        "Expected exactly one Braavos candidate at index 0"
    );

    let candidate = &braavos[0];

    // Parse both as Felt for canonical comparison (avoids leading-zero mismatches)
    let candidate_addr = Felt::from_hex(&candidate.address).unwrap();
    let expected_addr = Felt::from_hex(BRAAVOS_ACCOUNT_ADDRESS).unwrap();
    assert_eq!(
        candidate_addr, expected_addr,
        "Braavos candidate address must match the known test vector"
    );

    let candidate_pubk = Felt::from_hex(&candidate.public_key).unwrap();
    let expected_pubk = Felt::from_hex(BRAAVOS_PUBLIC_KEY).unwrap();
    assert_eq!(
        candidate_pubk, expected_pubk,
        "Braavos candidate public key must match the known test vector"
    );
}

/// The discovery-level counterpart to
/// `discovery_braavos_candidate_matches_known_address`: without it, a wrong
/// Argent constructor encoding yields an undeployable address unnoticed.
#[test]
fn discovery_argent_legacy_candidate_matches_known_address() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    let v040_hash = Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap();
    let matching: Vec<_> = candidates
        .iter()
        .filter(|c| {
            c.wallet_type == WalletType::ArgentLegacy
                && c.derivation_index == 0
                && Felt::from_hex(&c.class_hash).unwrap() == v040_hash
        })
        .collect();

    assert_eq!(
        matching.len(),
        1,
        "Expected exactly one ArgentLegacy v0.4.0 candidate at index 0"
    );

    let candidate = matching[0];

    let candidate_addr = Felt::from_hex(&candidate.address).unwrap();
    let expected_addr = Felt::from_hex(ARGENT_ACCOUNT_ADDRESS).unwrap();
    assert_eq!(
        candidate_addr, expected_addr,
        "ArgentLegacy v0.4.0 candidate must match the account deployed on Sepolia"
    );

    let candidate_pubk = Felt::from_hex(&candidate.public_key).unwrap();
    assert_eq!(
        candidate_pubk,
        Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap(),
        "ArgentLegacy candidate public key must match the known test vector"
    );
}

/// Verify that at least one ArgentLegacy candidate at index 0 has the correct
/// private/public key pair from the double derivation scheme.
#[test]
fn discovery_argent_legacy_candidate_has_correct_key() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    let legacy: Vec<_> = candidates
        .iter()
        .filter(|c| c.wallet_type == WalletType::ArgentLegacy && c.derivation_index == 0)
        .collect();

    assert!(
        !legacy.is_empty(),
        "Must have at least one ArgentLegacy candidate at index 0"
    );

    let expected_pk = Felt::from_hex(ARGENT_PRIVATE_KEY).unwrap();
    let expected_pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();

    let matching = legacy
        .iter()
        .filter(|c| {
            Felt::from_hex(&c.private_key).unwrap() == expected_pk
                && Felt::from_hex(&c.public_key).unwrap() == expected_pubk
        })
        .count();

    assert!(
        matching > 0,
        "At least one ArgentLegacy candidate must have the known private/public key pair"
    );
}

/// Verify that every candidate address is unique across all wallet types and indices.
#[test]
fn discovery_all_addresses_are_unique() {
    let candidates = generate_candidates(MNEMONIC, 2).unwrap();

    let mut seen = std::collections::HashSet::new();
    for candidate in &candidates {
        let addr = Felt::from_hex(&candidate.address).unwrap();
        assert!(
            seen.insert(addr),
            "Duplicate address found: {} (wallet_type={:?}, index={}, class_version={})",
            candidate.address,
            candidate.wallet_type,
            candidate.derivation_index,
            candidate.class_version
        );
    }

    assert_eq!(seen.len(), candidates.len(), "All addresses must be unique");
}

/// Verify that candidate count scales linearly with max_index.
#[test]
fn discovery_candidates_increase_with_max_index() {
    let count_1 = generate_candidates(MNEMONIC, 1).unwrap().len();
    let count_3 = generate_candidates(MNEMONIC, 3).unwrap().len();

    assert_eq!(
        count_3,
        count_1 * 3,
        "3 indices should produce exactly 3x the candidates of 1 index"
    );
}

/// Verify that an invalid mnemonic returns an error.
#[test]
fn discovery_invalid_mnemonic_returns_error() {
    let result = generate_candidates("not valid", 1);
    assert!(
        result.is_err(),
        "Invalid mnemonic must return Err, got {} candidates",
        result.unwrap().len()
    );
}

/// Verify that all candidate fields containing hex values start with "0x"
/// and parse as valid Felt values.
#[test]
fn discovery_each_candidate_has_valid_hex_fields() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    for candidate in &candidates {
        // All hex fields must start with "0x"
        assert!(
            candidate.address.starts_with("0x"),
            "Address must start with 0x: {}",
            candidate.address
        );
        assert!(
            candidate.public_key.starts_with("0x"),
            "Public key must start with 0x: {}",
            candidate.public_key
        );
        assert!(
            candidate.private_key.starts_with("0x"),
            "Private key must start with 0x: {}",
            candidate.private_key
        );
        assert!(
            candidate.class_hash.starts_with("0x"),
            "Class hash must start with 0x: {}",
            candidate.class_hash
        );

        // All hex fields must parse as valid Felt values
        assert!(
            Felt::from_hex(&candidate.address).is_ok(),
            "Address must be a valid Felt: {}",
            candidate.address
        );
        assert!(
            Felt::from_hex(&candidate.public_key).is_ok(),
            "Public key must be a valid Felt: {}",
            candidate.public_key
        );
        assert!(
            Felt::from_hex(&candidate.private_key).is_ok(),
            "Private key must be a valid Felt: {}",
            candidate.private_key
        );
        assert!(
            Felt::from_hex(&candidate.class_hash).is_ok(),
            "Class hash must be a valid Felt: {}",
            candidate.class_hash
        );
    }
}

/// Verify that different derivation indices produce different keys for the
/// same wallet type.
#[test]
fn discovery_different_indices_have_different_keys() {
    let candidates = generate_candidates(MNEMONIC, 2).unwrap();

    // Check each wallet type: index 0 and index 1 should have different public keys
    for wallet_type in [
        WalletType::Braavos,
        WalletType::Argent,
        WalletType::ArgentLegacy,
        WalletType::ArgentCairo0,
        WalletType::OpenZeppelin,
    ] {
        let idx0: Vec<_> = candidates
            .iter()
            .filter(|c| c.wallet_type == wallet_type && c.derivation_index == 0)
            .collect();
        let idx1: Vec<_> = candidates
            .iter()
            .filter(|c| c.wallet_type == wallet_type && c.derivation_index == 1)
            .collect();

        assert!(
            !idx0.is_empty() && !idx1.is_empty(),
            "Both indices must have candidates for {:?}",
            wallet_type
        );

        // Compare the first candidate's public key from each index
        let pubk_0 = Felt::from_hex(&idx0[0].public_key).unwrap();
        let pubk_1 = Felt::from_hex(&idx1[0].public_key).unwrap();
        assert_ne!(
            pubk_0, pubk_1,
            "{:?} index 0 and index 1 must have different public keys",
            wallet_type
        );
    }
}

/// Verify that each candidate has meaningful derivation metadata.
///
/// - `derivation_path` must be non-empty
/// - `class_version` must be non-empty
/// - Braavos should use the direct BIP-44 path format
/// - ArgentLegacy should describe the double derivation (ETH re-seed)
#[test]
fn discovery_candidate_contains_derivation_metadata() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    for candidate in &candidates {
        assert!(
            !candidate.derivation_path.is_empty(),
            "derivation_path must not be empty for {:?}",
            candidate.wallet_type
        );
        assert!(
            !candidate.class_version.is_empty(),
            "class_version must not be empty for {:?}",
            candidate.wallet_type
        );
    }

    // Braavos uses direct BIP-44 path
    let braavos = candidates
        .iter()
        .find(|c| c.wallet_type == WalletType::Braavos)
        .unwrap();
    assert!(
        braavos.derivation_path.contains("m/44'/9004'/0'/0/0"),
        "Braavos derivation_path should contain the BIP-44 path, got: {}",
        braavos.derivation_path
    );

    // ArgentLegacy describes the double derivation
    let legacy = candidates
        .iter()
        .find(|c| c.wallet_type == WalletType::ArgentLegacy)
        .unwrap();
    assert!(
        legacy.derivation_path.contains("reseed") || legacy.derivation_path.contains("60'"),
        "ArgentLegacy derivation_path should describe the double derivation, got: {}",
        legacy.derivation_path
    );
}
