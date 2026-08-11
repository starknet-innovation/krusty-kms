use super::*;
use std::collections::HashSet;

const TEST_MNEMONIC: &str =
    "person hunt couch artefact try half produce fatal large raw prison electric";

#[test]
fn test_generate_candidates_produces_results() {
    let candidates = generate_candidates(TEST_MNEMONIC, 2).unwrap();
    assert!(
        !candidates.is_empty(),
        "expected non-empty candidate list for valid mnemonic"
    );
}

#[test]
fn test_braavos_candidate_matches_known_address() {
    let candidates = generate_candidates(TEST_MNEMONIC, 1).unwrap();
    let braavos = candidates
        .iter()
        .find(|c| c.wallet_type == WalletType::Braavos && c.derivation_index == 0)
        .expect("expected a Braavos candidate at index 0");
    assert_eq!(
        braavos.address, "0x5ddbfaa0b1daab3e0d8a78b5ba5cdfa00431ac62ca3d31fe3e8fabdbbf01626",
        "Braavos address mismatch for test mnemonic"
    );
}

#[test]
fn test_argent_legacy_candidate_matches_known_key() {
    let candidates = generate_candidates(TEST_MNEMONIC, 1).unwrap();
    let legacy = candidates
        .iter()
        .find(|c| c.wallet_type == WalletType::ArgentLegacy && c.derivation_index == 0)
        .expect("expected an ArgentLegacy candidate at index 0");
    assert_eq!(
        legacy.expose_private_key().unwrap(),
        "0x72e62ef0a3dc57f2891f0f27bc60b6951854990968d07660c6f245f14de67c",
        "Argent legacy private key mismatch for test mnemonic"
    );
}

#[test]
fn test_candidate_debug_redacts_private_key() {
    let candidates = generate_candidates(TEST_MNEMONIC, 1).unwrap();
    let c = &candidates[0];
    let debug = format!("{:?}", c);
    assert!(debug.contains("private_key: \"***\""));
    assert!(!debug.contains(c.expose_private_key().unwrap()));
}

#[test]
fn test_candidate_default_serialize_omits_private_key() {
    let candidates = generate_candidates(TEST_MNEMONIC, 1).unwrap();
    let json = serde_json::to_value(&candidates[0]).unwrap();
    assert!(json.get("privateKey").is_none());
    assert!(json.get("address").is_some());

    let with_secrets = serde_json::to_value(candidates[0].with_secrets().unwrap()).unwrap();
    assert_eq!(
        with_secrets["privateKey"],
        candidates[0].expose_private_key().unwrap()
    );
}

#[test]
fn test_invalid_mnemonic_returns_error() {
    let result = generate_candidates("invalid mnemonic that is not valid at all", 1);
    assert!(result.is_err(), "expected error for invalid mnemonic");
}

#[test]
fn test_candidates_are_unique() {
    let candidates = generate_candidates(TEST_MNEMONIC, 3).unwrap();
    let mut seen = HashSet::new();
    for c in &candidates {
        assert!(
            seen.insert(&c.address),
            "duplicate address found: {}",
            c.address
        );
    }
}

/// A public-only serde round-trip loses the private key; access must fail
/// loudly instead of yielding an empty string (M-05).
#[test]
fn test_public_roundtrip_yields_loud_error_not_empty_key() {
    let candidates = generate_candidates(TEST_MNEMONIC, 1).unwrap();
    let json = serde_json::to_string(&candidates[0]).unwrap();
    let restored: CandidateAccount = serde_json::from_str(&json).unwrap();

    assert!(restored.expose_private_key().is_err());
    assert!(restored.with_secrets().is_err());
    assert!(restored.verify_key_binding().is_err());
}

/// Freshly generated candidates and keypairs must pass key↔public-key
/// re-verification (M-05).
#[test]
fn test_generated_candidates_pass_key_binding_verification() {
    for candidate in generate_candidates(TEST_MNEMONIC, 1).unwrap() {
        candidate.verify_key_binding().unwrap_or_else(|e| {
            panic!(
                "candidate {:?}/{} failed key binding: {e}",
                candidate.wallet_type, candidate.class_version
            )
        });
    }
    for keypair in derive_discovery_keypairs(TEST_MNEMONIC, 1).unwrap() {
        keypair.verify_key_binding().unwrap();
    }
}

/// A tampered candidate (key/public-key mismatch) must fail verification (M-05).
#[test]
fn test_tampered_candidate_fails_key_binding_verification() {
    let candidates = generate_candidates(TEST_MNEMONIC, 2).unwrap();
    let mut tampered = candidates[0].clone();
    // Splice in another candidate's public key.
    let other = candidates
        .iter()
        .find(|c| c.public_key != tampered.public_key)
        .expect("need a second distinct public key");
    tampered.public_key = other.public_key.clone();
    assert!(tampered.verify_key_binding().is_err());
}

/// OZ discovery must cover both salt policies: the deploy-flow default
/// (salt = public key) and the legacy salt = 0 variant (M-06).
#[test]
fn test_oz_candidates_cover_both_salt_policies() {
    let candidates = generate_candidates(TEST_MNEMONIC, 1).unwrap();
    let oz: Vec<_> = candidates
        .iter()
        .filter(|c| c.wallet_type == WalletType::OpenZeppelin)
        .collect();
    assert_eq!(oz.len(), 2, "expected salt-pubkey and salt-0 OZ candidates");
    assert!(oz.iter().any(|c| c.class_version == "v3.0.0 salt-pubkey"));
    assert!(oz.iter().any(|c| c.class_version == "v3.0.0"));
    assert_ne!(
        oz[0].address, oz[1].address,
        "the two salt policies must produce different addresses"
    );

    // The salt-pubkey variant must agree with the deploy-flow address helper.
    let salt_pubkey = oz
        .iter()
        .find(|c| c.class_version == "v3.0.0 salt-pubkey")
        .unwrap();
    let pubk = starknet_types_core::felt::Felt::from_hex(&salt_pubkey.public_key).unwrap();
    let class_hash = starknet_types_core::felt::Felt::from_hex(&salt_pubkey.class_hash).unwrap();
    let expected = crate::account::derive_oz_account_address(&pubk, &class_hash, None).unwrap();
    assert_eq!(
        starknet_types_core::felt::Felt::from_hex(&salt_pubkey.address).unwrap(),
        expected,
        "salt-pubkey candidate must match the deploy flow's derived address"
    );
}
