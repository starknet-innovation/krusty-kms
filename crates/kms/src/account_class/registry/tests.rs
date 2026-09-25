//! Tests for the registry module.

use super::*;
use crate::account_class::ArgentConstructorLayout;
use std::collections::HashSet;

fn felt(hex: &str) -> Felt {
    Felt::from_hex(hex).unwrap()
}

#[test]
fn every_class_hash_appears_once() {
    let classes = known_account_classes();
    let unique: HashSet<Felt> = classes.iter().map(|c| c.class_hash).collect();
    assert_eq!(
        unique.len(),
        classes.len(),
        "duplicate class hash in registry"
    );
}

#[test]
fn every_entry_has_a_role_and_deployment_entries_have_a_constructor() {
    for class in known_account_classes() {
        assert!(!class.roles.is_empty(), "{} has no role", class.label);
        assert_eq!(
            class.constructor.is_some(),
            class.is_deployment_class(),
            "{}: constructor shape must be present exactly for deployment classes",
            class.label
        );
        assert!(!class.source.is_empty(), "{} has no source", class.label);
    }
}

#[test]
fn braavos_entries_separate_deployment_from_implementation() {
    let base = lookup_account_class(&felt(BraavosAccount::BASE_CLASS_HASH_V100)).unwrap();
    assert_eq!(base.family, AccountFamily::Braavos);
    assert_eq!(base.roles, vec![ClassRole::Deployment]);
    assert_eq!(base.constructor, Some(ConstructorShape::PublicKey));

    let current = lookup_account_class(&felt(BraavosAccount::ACCOUNT_CLASS_HASH_V120)).unwrap();
    assert_eq!(current.roles, vec![ClassRole::Implementation]);
    assert_eq!(current.constructor, None);

    assert_eq!(deployment_classes(AccountFamily::Braavos).len(), 2);
    assert_eq!(implementation_classes(AccountFamily::Braavos).len(), 3);
}

#[test]
fn argent_cairo1_entries_play_both_roles_with_their_layout() {
    let v040 = lookup_account_class(&felt(ArgentAccount::CLASS_HASH)).unwrap();
    assert_eq!(v040.family, AccountFamily::Argent);
    assert_eq!(v040.version, "0.4.0");
    assert_eq!(v040.roles, DEPLOYMENT_AND_IMPLEMENTATION);
    assert_eq!(
        v040.constructor.and_then(ConstructorShape::argent_layout),
        Some(ArgentConstructorLayout::SignerWithOptionalGuardian)
    );

    let v030 = lookup_account_class(&felt(ArgentAccount::CLASS_HASH_V030)).unwrap();
    assert_eq!(
        v030.constructor.and_then(ConstructorShape::argent_layout),
        Some(ArgentConstructorLayout::OwnerGuardianFelts)
    );
}

/// An unupgraded Argent Cairo 0 account reports the *proxy* class on
/// chain, so the proxy is both deployment and implementation, and the
/// classes it delegates to are proxy targets: code the account runs that
/// no address ever reports.
#[test]
fn argent_cairo0_proxy_is_deployment_and_implementation() {
    let proxy = lookup_account_class(&ArgentCairo0::proxy_class_hash()).unwrap();
    assert_eq!(proxy.roles, DEPLOYMENT_AND_IMPLEMENTATION);
    assert_eq!(proxy.constructor, Some(ConstructorShape::ArgentCairo0Proxy));
    assert!(!proxy.is_proxy_target());

    let targets = proxy_target_classes(AccountFamily::Argent);
    assert_eq!(targets.len(), ArgentCairo0::known_implementations().len());
    for (implementation, _) in ArgentCairo0::known_implementations() {
        let class = lookup_account_class(&implementation).unwrap();
        assert_eq!(class.roles, vec![ClassRole::ProxyTarget]);
        assert!(!class.is_implementation_class(), "no address reports it");
        assert!(class.constructor.is_none());
        assert!(targets.iter().any(|t| t.class_hash == implementation));
    }

    // A signing allowlist built from the registry accepts the class an
    // unupgraded Cairo 0 account actually reports.
    assert!(implementation_classes(AccountFamily::Argent)
        .iter()
        .any(|class| class.class_hash == ArgentCairo0::proxy_class_hash()));
}

#[test]
fn openzeppelin_manifest_class_is_registered() {
    let oz: Vec<_> = known_account_classes()
        .into_iter()
        .filter(|c| c.family == AccountFamily::OpenZeppelin)
        .collect();
    assert!(!oz.is_empty(), "manifest classes must be in the registry");
    assert!(oz
        .iter()
        .all(|c| c.constructor == Some(ConstructorShape::PublicKey)));
}

#[test]
fn unknown_class_hash_is_not_found() {
    assert_eq!(lookup_account_class(&Felt::from(0xabcdu64)), None);
}

#[test]
fn json_uses_camel_case_fields_and_snake_case_values() {
    let base = lookup_account_class(&felt(BraavosAccount::CLASS_HASH)).unwrap();
    let json = serde_json::to_value(&base).unwrap();
    assert_eq!(json["family"], "braavos");
    assert_eq!(json["classHash"], format!("{:#x}", base.class_hash));
    assert_eq!(json["roles"], serde_json::json!(["deployment"]));
    assert_eq!(
        json["constructor"],
        serde_json::json!({
            "shape": "public_key",
            "fromSeed": "[public_key]",
            "withGuardian": null,
            "inputsOutsideSeed": [],
        })
    );
    assert!(json.get("class_hash").is_none());

    let v040 = lookup_account_class(&felt(ArgentAccount::CLASS_HASH)).unwrap();
    let json = serde_json::to_value(&v040).unwrap();
    assert_eq!(
        json["constructor"],
        serde_json::json!({
            "shape": "argent_signer_with_optional_guardian",
            "fromSeed": "[0, owner, 1]",
            "withGuardian": "[0, owner, 0, 0, guardian]",
            "inputsOutsideSeed": ["guardian"],
        })
    );
}
