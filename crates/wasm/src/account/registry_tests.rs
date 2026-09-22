//! Tests for the class registry, deployment inspection and the Braavos
//! deployment-class checks (issue #146).

use super::test_fixtures::{
    ARGENT_GUARDIAN_KEY, ARGENT_OWNER_KEY, BRAAVOS_V100_ADDRESS, BRAAVOS_V100_OWNER_KEY,
};
use super::*;
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

fn js_error_message(error: JsValue) -> String {
    error
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(&error, &JsValue::from_str("message"))
                .ok()
                .and_then(|value| value.as_string())
        })
        .unwrap_or_default()
}

/// Issue #146: a real Mainnet account deployed with the v1.0.0 base class.
/// Only that class reproduces it; the class the account runs today is an
/// implementation class and must be refused, not derived from.
#[wasm_bindgen_test]
fn test_derive_braavos_account_address_uses_base_classes_only() {
    let pk = BRAAVOS_V100_OWNER_KEY;
    let expected = BRAAVOS_V100_ADDRESS;
    let base_v100 = krusty_kms::BraavosAccount::BASE_CLASS_HASH_V100;
    assert_eq!(
        derive_braavos_account_address(pk, Some(base_v100.to_string())).unwrap(),
        expected
    );
    assert_ne!(derive_braavos_account_address(pk, None).unwrap(), expected);

    for implementation in [
        krusty_kms::BraavosAccount::LEGACY_CLASS_HASH,
        krusty_kms::BraavosAccount::ACCOUNT_CLASS_HASH_V120,
    ] {
        let err = derive_braavos_account_address(pk, Some(implementation.to_string()))
            .expect_err("implementation class must be rejected");
        let message = js_error_message(err);
        assert!(
            message.contains("implementation class"),
            "unexpected error: {message}"
        );
    }
    let err = derive_braavos_account_address(pk, Some("0xabcd".to_string()))
        .expect_err("unknown class must be rejected");
    assert!(js_error_message(err).contains("unknown Braavos class hash"));
}

#[wasm_bindgen_test]
fn test_get_account_class_registry_labels_roles() {
    let registry: Vec<serde_json::Value> =
        serde_json::from_str(&get_account_class_registry().unwrap()).unwrap();
    assert!(
        registry.len() >= 14,
        "expected the full registry, got {}",
        registry.len()
    );

    let find = |hash: &str| {
        let wanted = format!("{:#x}", Felt::from_hex(hash).unwrap());
        registry
            .iter()
            .find(|c| c["classHash"] == wanted)
            .unwrap_or_else(|| panic!("{hash} missing from registry"))
            .clone()
    };
    let current_impl = find(krusty_kms::BraavosAccount::ACCOUNT_CLASS_HASH_V120);
    assert_eq!(current_impl["family"], "braavos");
    assert_eq!(current_impl["roles"], serde_json::json!(["implementation"]));
    assert!(current_impl["constructor"].is_null());

    let base_v100 = find(krusty_kms::BraavosAccount::BASE_CLASS_HASH_V100);
    assert_eq!(base_v100["roles"], serde_json::json!(["deployment"]));
    assert_eq!(base_v100["constructor"]["shape"], "public_key");
    assert_eq!(base_v100["constructor"]["fromSeed"], "[public_key]");
    assert!(base_v100["constructor"]["withGuardian"].is_null());
    assert_eq!(
        base_v100["constructor"]["inputsOutsideSeed"],
        serde_json::json!([])
    );

    // The convention travels with the class: version- and guardian-dependent.
    let argent_v040 = find(krusty_kms::ArgentAccount::CLASS_HASH);
    assert_eq!(
        argent_v040["roles"],
        serde_json::json!(["deployment", "implementation"])
    );
    assert_eq!(
        argent_v040["constructor"]["shape"],
        "argent_signer_with_optional_guardian"
    );
    assert_eq!(argent_v040["constructor"]["fromSeed"], "[0, owner, 1]");
    assert_eq!(
        argent_v040["constructor"]["withGuardian"],
        "[0, owner, 0, 0, guardian]"
    );
    assert_eq!(
        argent_v040["constructor"]["inputsOutsideSeed"],
        serde_json::json!(["guardian"])
    );
    let argent_v031 = find(krusty_kms::ArgentAccount::CLASS_HASH_V031);
    assert_eq!(argent_v031["constructor"]["fromSeed"], "[owner, 0]");
    assert_eq!(
        argent_v031["constructor"]["withGuardian"],
        "[owner, guardian]"
    );
    assert!(argent_v040["source"]
        .as_str()
        .unwrap()
        .starts_with("https://"));

    // An unupgraded Argent Cairo 0 account reports the proxy class, so the
    // proxy is what a signing allowlist must accept; the classes behind it
    // are proxy targets no address reports.
    let proxy = find(krusty_kms::ArgentCairo0::PROXY_CLASS_HASH);
    assert_eq!(
        proxy["roles"],
        serde_json::json!(["deployment", "implementation"])
    );
    let target = find(krusty_kms::ArgentCairo0::IMPL_CLASS_HASH_V024);
    assert_eq!(target["roles"], serde_json::json!(["proxy_target"]));
    assert!(target["constructor"].is_null());
}

/// A guardian blocks discovery, not verification: given the address and the
/// guardian, the address reproduces from the seed key exactly.
#[wasm_bindgen_test]
fn test_derive_argent_account_address_with_guardian() {
    let pk = ARGENT_OWNER_KEY;
    let guardian = ARGENT_GUARDIAN_KEY;
    let guarded = derive_argent_account_address_with_guardian(pk, guardian, None).unwrap();
    assert_ne!(guarded, derive_argent_account_address(pk, None).unwrap());
    // Same as the raw formula with the Mainnet-observed (0, pk, 0, 0, guardian).
    let raw = calculate_contract_address(
        pk,
        krusty_kms::ArgentAccount::CLASS_HASH,
        vec![
            "0x0".into(),
            pk.into(),
            "0x0".into(),
            "0x0".into(),
            guardian.into(),
        ],
        "0x0",
    )
    .unwrap();
    assert_eq!(guarded, raw);
    // v0.3.1 takes (pk, guardian).
    let v031 = krusty_kms::ArgentAccount::CLASS_HASH_V031;
    assert_eq!(
        derive_argent_account_address_with_guardian(pk, guardian, Some(v031.to_string())).unwrap(),
        calculate_contract_address(pk, v031, vec![pk.into(), guardian.into()], "0x0").unwrap()
    );
    // A zero guardian is "no guardian" on every class, never the undeployable
    // literal [0, pk, 0, 0, 0] on v0.4.0+.
    for class_hash in [None, Some(v031.to_string())] {
        assert_eq!(
            derive_argent_account_address_with_guardian(pk, "0x0", class_hash.clone()).unwrap(),
            derive_argent_account_address(pk, class_hash).unwrap()
        );
    }
    let err = derive_argent_account_address_with_guardian(pk, guardian, Some("0xabcd".to_string()))
        .expect_err("unknown Argent class hash must be rejected");
    assert!(js_error_message(err).contains("unknown Argent class hash"));
}

#[wasm_bindgen_test]
fn test_inspect_account_deployment_distinguishes_derivable_from_not() {
    // Issue #146 fixture: deployed with the v1.0.0 base, runs an implementation.
    let pk = BRAAVOS_V100_OWNER_KEY;
    let base_v100 = krusty_kms::BraavosAccount::BASE_CLASS_HASH_V100;
    let derivable: serde_json::Value = serde_json::from_str(
        &inspect_account_deployment(base_v100, pk, vec![pk.to_string()]).unwrap(),
    )
    .unwrap();
    assert_eq!(derivable["derivability"], "from_seed");
    // The deploy fields bind to the real Mainnet account (issue #146).
    assert_eq!(derivable["address"], BRAAVOS_V100_ADDRESS);
    assert_eq!(derivable["known"], true);
    assert!(derivable["guardianPublicKey"].is_null());
    assert_eq!(derivable["class"]["family"], "braavos");
    assert_eq!(
        derivable["ownerPublicKey"],
        format!("{:#x}", Felt::from_hex(pk).unwrap())
    );
    assert!(derivable["reason"].is_null());

    let current: serde_json::Value = serde_json::from_str(
        &inspect_account_deployment(
            krusty_kms::BraavosAccount::LEGACY_CLASS_HASH,
            pk,
            vec![pk.to_string()],
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(current["derivability"], "not_from_seed");
    assert_eq!(current["reason"], "implementation_class");
}

#[wasm_bindgen_test]
fn test_inspect_account_deployment_reports_guardians_and_unknown_targets() {
    let pk = BRAAVOS_V100_OWNER_KEY;

    // Argent v0.4.0 with a Starknet guardian: exists, but not from a seed.
    let guarded: serde_json::Value = serde_json::from_str(
        &inspect_account_deployment(
            krusty_kms::ArgentAccount::CLASS_HASH,
            pk,
            vec![
                "0x0".into(),
                pk.into(),
                "0x0".into(),
                "0x0".into(),
                "0x1234".into(),
            ],
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(guarded["derivability"], "not_from_seed");
    assert_eq!(guarded["reason"], "guardian");
    assert_eq!(
        guarded["ownerPublicKey"],
        format!("{:#x}", Felt::from_hex(pk).unwrap())
    );
    assert_eq!(guarded["guardianPublicKey"], "0x1234");

    let unknown: serde_json::Value = serde_json::from_str(
        &inspect_account_deployment("0xabcd", pk, vec![pk.to_string()]).unwrap(),
    )
    .unwrap();
    assert_eq!(unknown["derivability"], "unknown_class");
    assert_eq!(unknown["known"], false);
    assert!(unknown["class"].is_null());

    // A known proxy pointing at an unknown implementation is not an unknown
    // class: the state stays consistent (`known` true, its own reason).
    let proxy_calldata = vec![
        "0xabcd".to_string(),
        format!("{:#x}", krusty_kms::ArgentCairo0::initialize_selector()),
        "0x2".to_string(),
        pk.to_string(),
        "0x0".to_string(),
    ];
    let unknown_target: serde_json::Value = serde_json::from_str(
        &inspect_account_deployment(
            krusty_kms::ArgentCairo0::PROXY_CLASS_HASH,
            pk,
            proxy_calldata,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(unknown_target["known"], true);
    assert_eq!(unknown_target["derivability"], "not_from_seed");
    assert_eq!(unknown_target["reason"], "unknown_proxy_implementation");

    // A class that only runs behind the proxy is not the class an upgraded
    // account reports, and the reason says which it is.
    let proxy_target: serde_json::Value = serde_json::from_str(
        &inspect_account_deployment(
            krusty_kms::ArgentCairo0::IMPL_CLASS_HASH_V024,
            pk,
            vec![pk.to_string()],
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(proxy_target["reason"], "proxy_target_class");
}
