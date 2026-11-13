//! Unit tests for the encryption boundary.

use super::*;
use wasm_bindgen_test::*;

const TEST_SCRYPT_N: u32 = 1024;

fn test_scrypt_n() -> JsValue {
    JsValue::from_f64(TEST_SCRYPT_N as f64)
}

fn test_password(offset: u8) -> String {
    (0..12)
        .map(|index| char::from(b'a' + index + offset))
        .collect()
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt_private_key_roundtrip() {
    let private_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let password = test_password(0);

    let encrypted =
        encrypt_private_key(private_key.into(), password.clone(), test_scrypt_n()).unwrap();

    let decrypted = decrypt_private_key(
        &encrypted.nonce,
        &encrypted.salt,
        &encrypted.encrypted_key,
        password,
        test_scrypt_n(),
    )
    .unwrap();

    assert_eq!(decrypted, private_key);
}

#[wasm_bindgen_test]
fn high_cost_decrypt_requires_explicit_export() {
    let private_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let password = test_password(0);
    let encrypted =
        encrypt_private_key(private_key.into(), password.clone(), test_scrypt_n()).unwrap();

    let err = decrypt_private_key(
        &encrypted.nonce,
        &encrypted.salt,
        &encrypted.encrypted_key,
        password.clone(),
        JsValue::from_f64((1 << 19) as f64),
    )
    .expect_err("default export must reject 512 MiB before KDF");
    let message = js_sys::Reflect::get(&err, &JsValue::from_str("message"))
        .unwrap()
        .as_string()
        .unwrap();
    assert!(message.contains("memory ceiling"));
    assert!(message.contains("decryptPrivateKeyHighCost"));
    assert!(message.starts_with("Serialization error:"));
    assert_eq!(
        js_sys::Reflect::get(&err, &JsValue::from_str("code"))
            .unwrap()
            .as_string()
            .as_deref(),
        Some("SERIALIZATION_ERROR")
    );

    assert_eq!(
        decrypt_private_key_high_cost(
            &encrypted.nonce,
            &encrypted.salt,
            &encrypted.encrypted_key,
            password,
            test_scrypt_n(),
        )
        .unwrap(),
        private_key
    );
}

#[wasm_bindgen_test]
fn scrypt_cost_rejects_js_integer_wrap_before_kdf() {
    let wrapped = JsValue::from_f64((1u64 << 32 | u64::from(TEST_SCRYPT_N)) as f64);
    assert!(parse_scrypt_n(&wrapped).is_err());
    assert!(parse_scrypt_n(&JsValue::from_f64(1024.5)).is_err());
    assert!(parse_scrypt_n(&JsValue::from_str("1024")).is_err());
    let private_key = "ab".repeat(32);
    assert!(encrypt_private_key(private_key, test_password(0), wrapped.clone()).is_err());
    assert!(encrypt_keystore("abandon about".into(), test_password(0), wrapped.clone()).is_err());
    let nonce = "11".repeat(24);
    let salt = "22".repeat(16);
    let ciphertext = "33".repeat(48);
    assert!(decrypt_private_key(
        &nonce,
        &salt,
        &ciphertext,
        test_password(0),
        wrapped.clone()
    )
    .is_err());
    assert!(
        decrypt_private_key_high_cost(&nonce, &salt, &ciphertext, test_password(0), wrapped)
            .is_err()
    );
}

#[wasm_bindgen_test]
fn malformed_scrypt_n_has_structured_error() {
    let nonce = "11".repeat(24);
    let salt = "22".repeat(16);
    let ciphertext = "33".repeat(48);
    for invalid in [
        JsValue::from_str("1024"),
        JsValue::from_f64(1024.5),
        JsValue::from_f64(f64::NAN),
        JsValue::from_f64(f64::INFINITY),
        JsValue::from_f64(f64::NEG_INFINITY),
        JsValue::from_f64(-1.0),
        JsValue::from_f64(3000.0),
        JsValue::from_f64((1 << 21) as f64),
        JsValue::from(js_sys::BigInt::new(&JsValue::from_str("1024")).unwrap()),
        JsValue::NULL,
        JsValue::UNDEFINED,
    ] {
        for high_cost in [false, true] {
            let error = if high_cost {
                decrypt_private_key_high_cost(
                    &nonce,
                    &salt,
                    &ciphertext,
                    test_password(0),
                    invalid.clone(),
                )
                .unwrap_err()
            } else {
                decrypt_private_key(
                    &nonce,
                    &salt,
                    &ciphertext,
                    test_password(0),
                    invalid.clone(),
                )
                .unwrap_err()
            };
            assert_serialization_error(&error, "scryptN");
        }
    }
}

#[wasm_bindgen_test]
fn direct_decryption_input_errors_are_structured() {
    let nonce = "11".repeat(24);
    let salt = "22".repeat(16);
    let ciphertext = "33".repeat(48);
    for (nonce, salt, ciphertext, detail) in [
        ("11".repeat(25), salt.clone(), ciphertext.clone(), "nonce"),
        (nonce.clone(), "22".repeat(129), ciphertext.clone(), "salt"),
        (nonce, salt, "33".repeat(1024 * 1024 + 1), "encrypted key"),
        (
            "zz".repeat(24),
            "22".repeat(16),
            "33".repeat(48),
            "nonce hex",
        ),
        (
            "11".repeat(24),
            "zz".repeat(16),
            "33".repeat(48),
            "salt hex",
        ),
        (
            "11".repeat(24),
            "22".repeat(16),
            "zz".repeat(48),
            "encrypted key hex",
        ),
    ] {
        let error = decrypt_private_key(
            &nonce,
            &salt,
            &ciphertext,
            test_password(0),
            test_scrypt_n(),
        )
        .unwrap_err();
        assert_serialization_error(&error, detail);
    }
}

fn assert_serialization_error(error: &JsValue, detail: &str) {
    let code = js_sys::Reflect::get(error, &JsValue::from_str("code")).unwrap();
    assert_eq!(code.as_string().as_deref(), Some("SERIALIZATION_ERROR"));
    let message = js_sys::Reflect::get(error, &JsValue::from_str("message"))
        .unwrap()
        .as_string()
        .unwrap();
    assert!(message.contains(detail), "{message}");
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt_with_key_roundtrip() {
    let plaintext = "some secret data";
    let key_hex = "0101010101010101010101010101010101010101010101010101010101010101";

    let encrypted = encrypt_with_key(plaintext.into(), key_hex.into()).unwrap();

    let decrypted =
        decrypt_with_key(&encrypted.nonce, &encrypted.ciphertext, key_hex.into()).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt_keystore_roundtrip() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = test_password(0);

    let keystore_json =
        encrypt_keystore(mnemonic.into(), password.clone(), test_scrypt_n()).unwrap();
    let decrypted = decrypt_keystore(&keystore_json, password).unwrap();

    assert_eq!(decrypted, mnemonic);
}
