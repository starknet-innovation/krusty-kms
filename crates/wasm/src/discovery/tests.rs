use super::*;
use wasm_bindgen_test::*;

const TEST_MNEMONIC: &str =
    "person hunt couch artefact try half produce fatal large raw prison electric";

#[wasm_bindgen_test]
fn test_generate_account_candidates_public_only() {
    let result = generate_account_candidates(TEST_MNEMONIC.into(), JsValue::from_f64(1.0));
    assert!(result.is_ok());
    let json = result.unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
    assert!(!parsed.is_empty(), "Should generate at least one candidate");

    // Verify camelCase field names
    let first = &parsed[0];
    assert!(first.get("walletType").is_some());
    assert!(first.get("classHash").is_some());
    assert!(first.get("address").is_some());
    assert!(first.get("publicKey").is_some());
    assert!(
        first.get("privateKey").is_none(),
        "default discovery API must omit privateKey"
    );
    assert!(first.get("derivationIndex").is_some());
    assert!(first.get("derivationPath").is_some());
    assert!(first.get("classVersion").is_some());

    // Verify snake_case names are NOT present
    assert!(first.get("wallet_type").is_none());
    assert!(first.get("class_hash").is_none());
    assert!(first.get("public_key").is_none());
    assert!(first.get("private_key").is_none());
    assert!(first.get("derivation_index").is_none());
    assert!(first.get("derivation_path").is_none());
    assert!(first.get("class_version").is_none());
}

#[wasm_bindgen_test]
fn test_generate_account_candidates_with_secrets() {
    let result =
        generate_account_candidates_with_secrets(TEST_MNEMONIC.into(), JsValue::from_f64(1.0));
    assert!(result.is_ok());
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result.unwrap()).unwrap();
    assert!(!parsed.is_empty());
    let first = &parsed[0];
    assert!(first.get("privateKey").is_some());
    assert!(first.get("publicKey").is_some());
    assert!(first.get("address").is_some());
}

#[wasm_bindgen_test]
fn test_generate_account_candidates_invalid_mnemonic() {
    let result = generate_account_candidates("not a valid mnemonic".into(), JsValue::from_f64(1.0));
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn test_generate_account_addresses_compact() {
    let result = generate_account_addresses(TEST_MNEMONIC.into(), JsValue::from_f64(1.0));
    assert!(result.is_ok());
    let json = result.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    // Should have key "0" for index 0
    assert!(parsed.get("0").is_some());
    // Compact path must never embed private key material
    assert!(!json.contains("privateKey"));
    assert!(!json.contains("private_key"));
}

/// The compact view must surface *every* address variant per wallet type.
/// Collapsing to one address per type hid deployed accounts in a recovery
/// path — notably it dropped the legacy `salt = 0` OpenZeppelin address once
/// the `salt = public_key` variant was added ahead of it.
#[wasm_bindgen_test]
fn test_generate_account_addresses_keeps_all_variants() {
    let json = generate_account_addresses(TEST_MNEMONIC.into(), JsValue::from_f64(1.0)).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let index0 = parsed.get("0").expect("index 0 present");

    let variants = |wallet_type: &str| {
        index0
            .get(wallet_type)
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("{wallet_type} entry is an array"))
            .clone()
    };
    let oz = variants("OpenZeppelin");
    assert_eq!(oz.len(), 2, "both OZ salt policies must be listed: {oz:?}");
    assert_ne!(oz[0], oz[1], "the two salt policies differ in address");
    // Every variant was silently collapsed to one address before this
    // change; each of these is an account a recovery could otherwise miss.
    for (wallet_type, expected) in [
        ("Braavos", 2),
        ("Argent", 4),
        ("ArgentLegacy", 4),
        ("ArgentCairo0", 4),
    ] {
        assert_eq!(variants(wallet_type).len(), expected, "{wallet_type}");
    }

    // Every address in the compact view must also appear in the full
    // candidate list, so the two APIs cannot drift.
    let full: Vec<serde_json::Value> = serde_json::from_str(
        &generate_account_candidates(TEST_MNEMONIC.into(), JsValue::from_f64(1.0)).unwrap(),
    )
    .unwrap();
    let full_addrs: Vec<&str> = full
        .iter()
        .map(|c| c.get("address").unwrap().as_str().unwrap())
        .collect();
    for entry in index0.as_object().unwrap().values() {
        for addr in entry.as_array().unwrap() {
            let addr = addr.as_str().unwrap();
            assert!(full_addrs.contains(&addr), "{addr} missing from full list");
        }
    }
}

#[wasm_bindgen_test]
fn test_derive_discovery_keypairs_public_only() {
    let result = derive_discovery_keypairs(TEST_MNEMONIC.into(), JsValue::from_f64(1.0)).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
    assert!(!parsed.is_empty());
    assert!(parsed[0].get("publicKey").is_some());
    assert!(parsed[0].get("privateKey").is_none());
}

#[wasm_bindgen_test]
fn test_discover_accounts_public_only() {
    let result =
        discover_accounts_from_mnemonic(TEST_MNEMONIC.into(), JsValue::from_f64(1.0)).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let keypairs = parsed.get("keypairs").unwrap().as_array().unwrap();
    let candidates = parsed.get("candidates").unwrap().as_array().unwrap();
    assert!(!keypairs.is_empty());
    assert!(!candidates.is_empty());
    assert!(keypairs[0].get("privateKey").is_none());
    assert!(candidates[0].get("privateKey").is_none());
}
