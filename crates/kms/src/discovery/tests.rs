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
        legacy.expose_private_key(),
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
    assert!(!debug.contains(c.expose_private_key()));
}

#[test]
fn test_candidate_default_serialize_omits_private_key() {
    let candidates = generate_candidates(TEST_MNEMONIC, 1).unwrap();
    let json = serde_json::to_value(&candidates[0]).unwrap();
    assert!(json.get("privateKey").is_none());
    assert!(json.get("address").is_some());

    let with_secrets = serde_json::to_value(candidates[0].with_secrets()).unwrap();
    assert_eq!(
        with_secrets["privateKey"],
        candidates[0].expose_private_key()
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
