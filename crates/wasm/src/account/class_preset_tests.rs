//! Account class preset tests: Argent, Braavos and OZ address derivation,
//! contract address calculation and the class-hash registry export.

use super::*;
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

#[wasm_bindgen_test]
fn test_derive_argent_account_address() {
    let pk = "0x78936b8dc426c649fccf3a9a8022b9795bdcd558dfb83956d66a25ae76992df";
    let addr = derive_argent_account_address(pk, None).unwrap();
    assert!(addr.starts_with("0x"));
    assert_ne!(addr, "0x0");
}

#[wasm_bindgen_test]
fn test_derive_argent_account_address_rejects_unknown_class_hash() {
    let pk = "0x78936b8dc426c649fccf3a9a8022b9795bdcd558dfb83956d66a25ae76992df";
    // A known Argent class hash is accepted and derives the same address as
    // the default, which is that class.
    let known = "0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f";
    assert_eq!(
        derive_argent_account_address(pk, Some(known.to_string())).unwrap(),
        derive_argent_account_address(pk, None).unwrap()
    );

    // An unrecognised class hash has no known constructor layout, so the
    // export must fail rather than derive an address from a guess.
    let err = derive_argent_account_address(pk, Some("0xabcd".to_string()))
        .expect_err("unknown Argent class hash must be rejected");
    let message = js_error_message(err);
    assert!(
        message.contains("unknown Argent class hash"),
        "unexpected error: {message}"
    );
}

#[wasm_bindgen_test]
fn test_derive_braavos_account_address() {
    let pk = "0x78936b8dc426c649fccf3a9a8022b9795bdcd558dfb83956d66a25ae76992df";
    let addr = derive_braavos_account_address(pk, None).unwrap();
    assert!(addr.starts_with("0x"));
    assert_ne!(addr, "0x0");
}

#[wasm_bindgen_test]
fn test_different_account_types_different_addresses() {
    let pk = "0x78936b8dc426c649fccf3a9a8022b9795bdcd558dfb83956d66a25ae76992df";
    let argent_addr = derive_argent_account_address(pk, None).unwrap();
    let braavos_addr = derive_braavos_account_address(pk, None).unwrap();
    assert_ne!(argent_addr, braavos_addr);
}

#[wasm_bindgen_test]
fn test_calculate_contract_address() {
    let address_salt = format!("0x{:x}", usize::from(true));
    let class_hash = "0xdeadbeef";
    let calldata = vec!["0x1".to_string(), "0x2".to_string()];
    let deployer = "0x0";
    let addr = calculate_contract_address(&address_salt, class_hash, calldata, deployer).unwrap();
    assert!(addr.starts_with("0x"));
    assert_ne!(addr, "0x0");
}

#[wasm_bindgen_test]
fn test_get_account_class_hashes() {
    let json_str = get_account_class_hashes();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed.get("argent").is_some());
    assert!(parsed.get("argent_legacy").is_some());
    assert!(parsed.get("braavos").is_some());
    assert!(parsed.get("oz").is_some());

    // Argent Cairo 1 classes, including v0.5.0.
    let argent = parsed.get("argent").unwrap();
    for version in ["0.5.0", "0.4.0", "0.3.1", "0.3.0"] {
        assert!(argent.get(version).is_some(), "argent {version}");
    }

    // Cairo 0 labels follow Argent X's own constants; the former "0.2.0" key
    // duplicated the proxy hash and is gone.
    let legacy = parsed.get("argent_legacy").unwrap();
    assert!(legacy.get("proxy").is_some());
    for version in ["0.2.4", "0.2.3", "0.2.2", "0.2.1"] {
        assert!(legacy.get(version).is_some(), "argent_legacy {version}");
    }
    assert!(legacy.get("0.2.0").is_none());

    // Braavos: the historical keys are kept, the missing classes are added.
    let braavos = parsed.get("braavos").unwrap();
    assert_eq!(braavos["1.0.0"], krusty_kms::BraavosAccount::CLASS_HASH);
    assert_eq!(
        braavos["legacy"],
        krusty_kms::BraavosAccount::LEGACY_CLASS_HASH
    );
    assert_eq!(
        braavos["base-1.0.0"],
        krusty_kms::BraavosAccount::BASE_CLASS_HASH_V100
    );
    assert_eq!(
        braavos["account-1.1.0"],
        krusty_kms::BraavosAccount::ACCOUNT_CLASS_HASH_V110
    );
    assert_eq!(
        braavos["account-1.2.0"],
        krusty_kms::BraavosAccount::ACCOUNT_CLASS_HASH_V120
    );
}
