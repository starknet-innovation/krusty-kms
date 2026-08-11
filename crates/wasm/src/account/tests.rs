use super::*;
use crate::types::{WasmAccountState, WasmCiphertext};
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

const TEST_MNEMONIC: &str =
    "habit hope tip crystal because grunt nation idea electric witness alert like";

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
fn test_generate_mnemonic() {
    let mnemonic = generate_mnemonic(Some(12)).unwrap();
    assert!(validate_mnemonic(&mnemonic));
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 12);
}

#[wasm_bindgen_test]
fn test_account_from_mnemonic() {
    let contract = "0x1234";
    let account = WasmAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract, None);
    assert!(account.is_ok());

    let acc = account.unwrap();
    assert!(acc.owner_public_key_hex().is_ok());
}

#[wasm_bindgen_test]
fn test_account_from_private_key() {
    let contract = "0x1234";
    let private_key = "0x2a"; // 42 in hex
    let account = WasmAccount::from_private_key(private_key, contract);
    assert!(account.is_ok());
}

#[wasm_bindgen_test]
fn test_derive_keypair() {
    let kp = derive_keypair(TEST_MNEMONIC, 0, 0, None);
    assert!(kp.is_ok());

    let keypair = kp.unwrap();
    assert!(keypair.private_key.starts_with("0x"));
    assert!(keypair.public_key_x.starts_with("0x"));
}

#[wasm_bindgen_test]
fn test_state_management() {
    let contract = "0x1234";
    let mut account = WasmAccount::from_private_key("0x2a", contract).unwrap();

    let new_state = WasmAccountState::new("1000".to_string(), "500".to_string(), 5).unwrap();
    account.update_state(new_state).unwrap();

    let state = account.get_state();
    assert_eq!(state.balance, "1000");
    assert_eq!(state.pending_balance, "500");
    assert_eq!(state.nonce, 5);
    assert_eq!(state.total_balance().unwrap(), "1500");
}

#[wasm_bindgen_test]
fn test_state_rejects_invalid_balance_strings() {
    let err = WasmAccountState::new("abc".to_string(), "500".to_string(), 5).unwrap_err();
    assert_eq!(
        js_error_message(err),
        "Serialization error: balance must be a valid unsigned decimal string"
    );
}

#[wasm_bindgen_test]
fn test_total_balance_rejects_invalid_state_fields() {
    let state = WasmAccountState {
        balance: "oops".to_string(),
        pending_balance: "500".to_string(),
        nonce: 5,
    };

    let err = state.total_balance().unwrap_err();
    assert_eq!(
        js_error_message(err),
        "Serialization error: balance must be a valid unsigned decimal string"
    );
}

#[wasm_bindgen_test]
fn test_account_total_balance_rejects_overflow() {
    let contract = "0x1234";
    let mut account = WasmAccount::from_private_key("0x2a", contract).unwrap();
    let overflow_state = WasmAccountState::new(u128::MAX.to_string(), "1".to_string(), 0).unwrap();
    account.update_state(overflow_state).unwrap();

    let err = account.total_balance().unwrap_err();
    assert_eq!(
        js_error_message(err),
        "Invalid amount: account total balance overflow"
    );
}

#[wasm_bindgen_test]
fn test_update_state_rejects_invalid_pending_balance() {
    let contract = "0x1234";
    let mut account = WasmAccount::from_private_key("0x2a", contract).unwrap();
    let invalid_state = WasmAccountState {
        balance: "1000".to_string(),
        pending_balance: "oops".to_string(),
        nonce: 5,
    };

    let err = account.update_state(invalid_state).unwrap_err();
    assert_eq!(
        js_error_message(err),
        "Serialization error: pending_balance must be a valid unsigned decimal string"
    );
}

#[wasm_bindgen_test]
fn test_has_sufficient_balance_rejects_invalid_amounts() {
    let account = WasmAccount::from_private_key("0x2a", "0x1234").unwrap();
    let error = account.has_sufficient_balance("not-a-number").unwrap_err();
    assert_eq!(
        js_error_message(error),
        "Serialization error: invalid decimal amount"
    );
}

#[wasm_bindgen_test]
fn test_decrypt_to_point_represents_zero_balance_as_identity() {
    let account = WasmAccount::from_private_key("0x2a", "0x1234").unwrap();
    let public_key = account.inner.owner_public_key().clone();
    let encryption = krusty_kms_crypto::ElGamal::encrypt(
        &Felt::ZERO,
        &public_key,
        &Felt::from(999u64),
        &Felt::from(7u64),
    )
    .unwrap();
    let l = encryption.l.to_affine().unwrap();
    let r = encryption.r.to_affine().unwrap();

    let ciphertext = WasmCiphertext {
        l_x: format!("{:#x}", l.x()),
        l_y: format!("{:#x}", l.y()),
        r_x: format!("{:#x}", r.x()),
        r_y: format!("{:#x}", r.y()),
    };

    let decrypted = account.decrypt_to_point(&ciphertext).unwrap();
    assert!(decrypted.is_identity);
    assert!(decrypted.x.is_none());
    assert!(decrypted.y.is_none());
}

#[wasm_bindgen_test]
fn test_derive_starknet_keypair() {
    let kp = derive_starknet_keypair(TEST_MNEMONIC, 0, 0, None);
    assert!(kp.is_ok());

    let keypair = kp.unwrap();
    assert!(keypair.private_key.starts_with("0x"));
    assert!(keypair.public_key_x.starts_with("0x"));

    // Starknet keypair should be different from Tongo keypair (different coin types)
    let tongo_kp = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    assert_ne!(keypair.private_key, tongo_kp.private_key);
}

#[wasm_bindgen_test]
fn test_derive_oz_account_address() {
    // First derive a Starknet keypair
    let kp = derive_starknet_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();

    // Use the latest manifest-backed OZ class hash.
    let oz_class_hash = "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381";

    let address = derive_oz_account_address(&kp.public_key_x, oz_class_hash, None);
    assert!(address.is_ok());

    let addr = address.unwrap();
    assert!(addr.starts_with("0x"));
}

#[wasm_bindgen_test]
fn test_coin_type_constants() {
    assert_eq!(get_starknet_coin_type(), 9004);
    assert_eq!(get_tongo_coin_type(), 5454);
    assert_eq!(get_nostr_coin_type(), 1237);
}

#[wasm_bindgen_test]
fn test_derive_nostr_keypair() {
    let kp = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None);
    assert!(kp.is_ok());

    let keypair = kp.unwrap();
    // Nostr keys are 64 hex chars (32 bytes) without 0x prefix
    assert_eq!(keypair.private_key.len(), 64);
    assert_eq!(keypair.public_key.len(), 64);
    // Should be valid hex
    assert!(hex::decode(&keypair.private_key).is_ok());
    assert!(hex::decode(&keypair.public_key).is_ok());
}

#[wasm_bindgen_test]
fn test_nostr_keypair_different_from_starknet() {
    let nostr_kp = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let starknet_kp = derive_starknet_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let tongo_kp = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();

    // Nostr keypair should be different from both Starknet and Tongo keypairs
    // (different curves and coin types)
    assert_ne!(
        nostr_kp.private_key,
        starknet_kp.private_key.trim_start_matches("0x")
    );
    assert_ne!(
        nostr_kp.private_key,
        tongo_kp.private_key.trim_start_matches("0x")
    );
}

#[wasm_bindgen_test]
fn test_nostr_keypair_deterministic() {
    // Same mnemonic should produce same keypair
    let kp1 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    let kp2 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
    assert_eq!(kp1.private_key, kp2.private_key);
    assert_eq!(kp1.public_key, kp2.public_key);

    // Different index should produce different keypair
    let kp3 = derive_nostr_keypair(TEST_MNEMONIC, 1, 0, None).unwrap();
    assert_ne!(kp1.private_key, kp3.private_key);
}

// -------------------------------------------------------------------
// Category G: Account class preset tests
// -------------------------------------------------------------------

#[wasm_bindgen_test]
fn test_derive_argent_account_address() {
    let pk = "0x78936b8dc426c649fccf3a9a8022b9795bdcd558dfb83956d66a25ae76992df";
    let addr = derive_argent_account_address(pk, None).unwrap();
    assert!(addr.starts_with("0x"));
    assert_ne!(addr, "0x0");
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

    // Verify argent_legacy contains the expected Cairo 0 class hashes
    let legacy = parsed.get("argent_legacy").unwrap();
    assert!(legacy.get("proxy").is_some());
    assert!(legacy.get("0.2.3").is_some());
    assert!(legacy.get("0.2.2").is_some());
    assert!(legacy.get("0.2.1").is_some());
    assert!(legacy.get("0.2.0").is_some());
}
