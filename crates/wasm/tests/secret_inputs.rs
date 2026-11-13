//! Secret inputs remain owned and wiped. Felt strings use decimal digits or
//! prefixed hexadecimal; byte strings retain their own formats.
//!
//! Every secret argument is passed with `.into()`, so this file compiles
//! against both the borrowed (`&str`) and the owned (`String`) signature, and
//! it originally ran against both.

use krusty_kms_wasm::{account, encryption, signing, strk20, utils, WasmAccount};
use starknet_types_core::felt::Felt;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// BIP-340 test vector 1 secret key: it has letters, so case matters.
const NOSTR_KEY: &str = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF";
const SYMMETRIC_KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const FIELD_PRIME: &str = "0x0800000000000011000000000000000000000000000000000000000000000001";
const SCRYPT_N: u32 = 1024;

fn message(error: JsValue) -> String {
    error
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(&error, &JsValue::from_str("message"))
                .ok()
                .and_then(|value| value.as_string())
        })
        .unwrap_or_default()
}

fn key_bytes(hex_value: &str) -> [u8; 32] {
    hex::decode(hex_value).unwrap().try_into().unwrap()
}

/// A 64-character key with one character replaced.
fn with_char_at(key: &str, index: usize, replacement: &str) -> String {
    format!("{}{replacement}{}", &key[..index], &key[index + 1..])
}

#[wasm_bindgen_test]
fn nostr_private_key_hex_is_parsed_as_before() {
    let expected = hex::encode(krusty_kms::nostr_public_key(&key_bytes(NOSTR_KEY)).unwrap());
    let refused = |input: &str| message(signing::nostr_public_key(input.into()).unwrap_err());

    assert_eq!(
        signing::nostr_public_key(NOSTR_KEY.into()).unwrap(),
        expected
    );
    let lower = NOSTR_KEY.to_ascii_lowercase();
    assert_eq!(
        signing::nostr_public_key(lower.as_str().into()).unwrap(),
        expected
    );
    let padded = format!(" \t{NOSTR_KEY}\n");
    assert_eq!(
        signing::nostr_public_key(padded.as_str().into()).unwrap(),
        expected
    );

    let length = "Nostr private key must be exactly 32 bytes (64 hex chars)";
    for (input, error) in [
        (
            format!("0x{NOSTR_KEY}"),
            "Nostr private key must not have 0x prefix",
        ),
        (
            format!("0X{NOSTR_KEY}"),
            "Nostr private key must not have 0x prefix",
        ),
        (
            NOSTR_KEY[..63].to_string(),
            "Invalid Nostr private key hex: Odd number of digits",
        ),
        (NOSTR_KEY[..62].to_string(), length),
        (format!("{NOSTR_KEY}00"), length),
        (String::new(), length),
        (
            with_char_at(NOSTR_KEY, 5, "g"),
            "Invalid Nostr private key hex: Invalid character 'g' at position 5",
        ),
        // A bad character is reported before a bad length, as `hex::decode` does.
        (
            with_char_at(&NOSTR_KEY[..62], 1, "z"),
            "Invalid Nostr private key hex: Invalid character 'z' at position 1",
        ),
        // Non-ASCII: the first byte of the UTF-8 sequence is reported.
        (
            format!("é{}", &NOSTR_KEY[..62]),
            "Invalid Nostr private key hex: Invalid character 'Ã' at position 0",
        ),
        (
            format!("é{NOSTR_KEY}"),
            "Invalid Nostr private key hex: Invalid character 'Ã' at position 0",
        ),
    ] {
        assert_eq!(refused(&input), error, "{input:?}");
    }
    assert!(refused(&"00".repeat(32)).starts_with("Nostr public key derivation failed: "));

    let event_id = "11".repeat(32);
    let signature = signing::sign_nostr_event_id(NOSTR_KEY.into(), &event_id).unwrap();
    assert_eq!(signature.public_key, expected);
    let short = &NOSTR_KEY[..62];
    let error = signing::sign_nostr_message(short.into(), "0x00").unwrap_err();
    assert_eq!(message(error), length);
}

#[wasm_bindgen_test]
fn grind_seed_hex_is_parsed_as_before() {
    let seed = "86f3e7293141f20a8baff320e8ee4accb9d4a4bf2b4d295e8cee784db46e0519";
    let expected = format!("{:#x}", krusty_kms::grind_key(&key_bytes(seed)).unwrap());
    for input in [seed.to_string(), format!("0x{seed}"), format!("0X{seed}")] {
        assert_eq!(utils::grind_key(input.as_str().into()).unwrap(), expected);
    }
    for (input, error) in [
        (
            seed[..62].to_string(),
            "Seed must be exactly 32 bytes, got 31",
        ),
        (format!("{seed}00"), "Seed must be exactly 32 bytes, got 33"),
        (String::new(), "Seed must be exactly 32 bytes, got 0"),
        ("0x".to_string(), "Seed must be exactly 32 bytes, got 0"),
        (
            seed[..63].to_string(),
            "Invalid hex seed: Odd number of digits",
        ),
        (
            format!("0x0x{seed}"),
            "Invalid hex seed: Invalid character 'x' at position 1",
        ),
        (
            with_char_at(seed, 7, "-"),
            "Invalid hex seed: Invalid character '-' at position 7",
        ),
    ] {
        let refused = utils::grind_key(input.as_str().into()).unwrap_err();
        assert_eq!(message(refused), error, "{input:?}");
    }
}

#[wasm_bindgen_test]
fn symmetric_key_and_plaintext_are_handled_as_before() {
    let plaintext = "naïve plaintext ✓";
    let sealed = encryption::encrypt_with_key(plaintext.into(), SYMMETRIC_KEY.into()).unwrap();
    let opened =
        encryption::decrypt_with_key(&sealed.nonce, &sealed.ciphertext, SYMMETRIC_KEY.into());
    assert_eq!(opened.unwrap(), plaintext);

    for (input, error) in [
        (
            format!("0x{SYMMETRIC_KEY}"),
            "Invalid key hex: Invalid character 'x' at position 1",
        ),
        (
            SYMMETRIC_KEY[..62].to_string(),
            "Key must be exactly 32 bytes (64 hex chars)",
        ),
        (
            SYMMETRIC_KEY[..63].to_string(),
            "Invalid key hex: Odd number of digits",
        ),
    ] {
        let sealing = encryption::encrypt_with_key(plaintext.into(), input.as_str().into());
        assert_eq!(message(sealing.unwrap_err()), error, "{input:?}");
        let opening =
            encryption::decrypt_with_key(&sealed.nonce, &sealed.ciphertext, input.as_str().into());
        assert_eq!(message(opening.unwrap_err()), error, "{input:?}");
    }

    let binary =
        krusty_kms::encryption::encrypt_with_key(&[0x61, 0xff], &key_bytes(SYMMETRIC_KEY)).unwrap();
    let error = encryption::decrypt_with_key(
        &hex::encode(&binary.nonce),
        &hex::encode(&binary.ciphertext),
        SYMMETRIC_KEY.into(),
    )
    .unwrap_err();
    assert_eq!(
        message(error),
        "Decrypted data is not valid UTF-8: invalid utf-8 sequence of 1 bytes from index 1"
    );
}

#[wasm_bindgen_test]
fn strk20_private_key_felts_use_decimal_or_prefixed_hex() {
    let scope = ("0x534e5f5345504f4c4941", "0x123");
    let derive = |key: &str| {
        strk20::derive_scoped_strk20_viewing_key(key.into(), scope.0, scope.1).map_err(message)
    };
    let expected = derive("0x1").unwrap();
    for accepted in ["1", "0x0001", &format!("0x{:064x}", 1)] {
        assert_eq!(derive(accepted).unwrap(), expected, "{accepted:?}");
    }
    assert_eq!(derive("0xAbC").unwrap(), derive("0xabc").unwrap());
    assert_eq!(derive("10").unwrap(), derive("0xa").unwrap());
    assert_ne!(derive("10").unwrap(), derive("0x10").unwrap());
    assert_eq!(derive("0X1").unwrap(), expected);

    let out_of_range = "Invalid private key: hex felt exceeds the field modulus";
    assert_eq!(derive(FIELD_PRIME).unwrap_err(), out_of_range);
    for input in [
        format!("0x{}", "f".repeat(64)),
        format!("0x{}", "1".repeat(65)),
        "0x".to_string(),
        "0x1 ".to_string(),
        "0x1é".to_string(),
        String::new(),
    ] {
        assert!(derive(&input).is_err(), "{input:?}");
    }

    let hash = strk20::strk20_viewing_key_message_hash(scope.0, scope.1).unwrap();
    let signature =
        krusty_kms::sign_stark_hash(&Felt::ONE, &Felt::from_hex(&hash).unwrap()).unwrap();
    let public_key = format!("{:#x}", signature.public_key);
    let (r, s) = (
        format!("{:#066x}", signature.r),
        format!("{:#x}", signature.s),
    );
    let folded =
        strk20::fold_strk20_viewing_key(&public_key, &hash, r.as_str().into(), s.as_str().into());
    assert_eq!(folded.unwrap(), expected);
    let error =
        strk20::fold_strk20_viewing_key(&public_key, &hash, FIELD_PRIME.into(), s.as_str().into());
    assert_eq!(
        message(error.unwrap_err()),
        "Invalid signature r: hex felt exceeds the field modulus"
    );
}

#[wasm_bindgen_test]
fn stark_private_key_felts_use_decimal_or_prefixed_hex() {
    let expected = format!(
        "{:#x}",
        krusty_kms::stark_public_key(&Felt::from_hex("0x1").unwrap()).unwrap()
    );
    assert_eq!(signing::stark_public_key("0x1".into()).unwrap(), expected);
    assert_eq!(signing::stark_public_key("1".into()).unwrap(), expected);
    let decimal_signature = signing::sign_stark_hash("1".into(), "10").unwrap();
    let hex_signature = signing::sign_stark_hash("0x1".into(), "0xa").unwrap();
    assert_eq!(decimal_signature.r, hex_signature.r);
    assert_eq!(decimal_signature.s, hex_signature.s);
    let hex_error = "Invalid private key: expected decimal digits or a 0x-prefixed hex felt";
    let error = signing::sign_stark_hash("zz".into(), "0x2").unwrap_err();
    assert_eq!(message(error), hex_error);
    assert!(
        message(signing::stark_public_key("0x0".into()).unwrap_err())
            .starts_with("Invalid private key: ")
    );

    assert!(utils::is_valid_stark_private_key("0x1".into()));
    for refused in ["0x0", "zz", "", "0x1é"] {
        assert!(
            !utils::is_valid_stark_private_key(refused.into()),
            "{refused:?}"
        );
    }

    let g = krusty_kms_wasm::get_generator();
    let one = krusty_kms_wasm::scalar_mul_generator("0x1".into()).unwrap();
    assert_eq!(
        (one.x.as_str(), one.y.as_str()),
        (g.x.as_str(), g.y.as_str())
    );
    let two = krusty_kms_wasm::scalar_mul("0x2".into(), &g.x, &g.y).unwrap();
    let doubled = krusty_kms_wasm::scalar_mul_generator("0x02".into()).unwrap();
    assert_eq!((two.x, two.y), (doubled.x.clone(), doubled.y.clone()));
    let error = krusty_kms_wasm::scalar_mul_generator("zz".into()).unwrap_err();
    assert_eq!(
        message(error),
        "Invalid scalar: expected decimal digits or a 0x-prefixed hex felt"
    );

    assert!(WasmAccount::from_private_key("0x1".into(), "0x123").is_ok());
    let error = WasmAccount::from_private_key("zz".into(), "0x123")
        .err()
        .unwrap();
    assert!(message(error).contains("expected decimal digits or a 0x-prefixed hex felt"));
}

#[wasm_bindgen_test]
fn mnemonics_and_passwords_are_handled_as_before() {
    assert!(account::validate_mnemonic(MNEMONIC.into()));
    for refused in [
        "abandon",
        "",
        "abándon abandon abandon abandon abandon abandon",
    ] {
        assert!(!account::validate_mnemonic(refused.into()), "{refused:?}");
    }

    let expected = krusty_kms::derive_keypair(MNEMONIC, 0, 0, None).unwrap();
    let keypair = account::derive_keypair(MNEMONIC.into(), 0, 0, None).unwrap();
    assert_eq!(
        keypair.private_key,
        *expected.private_key.expose_secret_hex()
    );
    let error = account::derive_keypair("abandon".into(), 0, 0, None)
        .err()
        .unwrap();
    assert_eq!(message(error), "Invalid mnemonic: BadWordCount(1)");

    let password = "pässwörd ✓";
    let sealed =
        encryption::encrypt_keystore(MNEMONIC.into(), password.into(), SCRYPT_N.into()).unwrap();
    let opened = encryption::decrypt_keystore(&sealed, password.into()).unwrap();
    assert_eq!(opened, MNEMONIC);
    let error = encryption::decrypt_keystore(&sealed, "passwörd ✓".into()).unwrap_err();
    assert_eq!(
        message(error),
        "Crypto error: Decryption failed: aead::Error"
    );

    let key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let sealed =
        encryption::encrypt_private_key(key.into(), password.into(), SCRYPT_N.into()).unwrap();
    let opened = encryption::decrypt_private_key(
        &sealed.nonce,
        &sealed.salt,
        &sealed.encrypted_key,
        password.into(),
        SCRYPT_N.into(),
    );
    assert_eq!(opened.unwrap(), key);
}
