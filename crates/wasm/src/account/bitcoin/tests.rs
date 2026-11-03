//! Boundary tests: the WASM wrappers reproduce the core vectors, parse keys
//! strictly, and surface refusals as JS errors.

use super::*;
use wasm_bindgen_test::*;

const BIP84_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// BIP-84 m/84'/0'/0'/0/0 (WIF KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d).
const BIP84_KEY: &str = "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3";
/// BIP-322 vector key (WIF L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k).
const BIP322_KEY: &str = "bb051cd0dda0246f33c5a9e133ebd8e7bc02a92af6c41adc131ccd7826c5b004";
const BIP322_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
/// A PSBT whose input 0 spends a coin of `BIP84_KEY` with full UTXO data;
/// input 1 belongs to someone else (built by the core crate's PSBT tests).
const PSBT: &str = "cHNidP8BAIcCAAAAAtCg1+RXnSr2DVIGkqDIIJJoBYZosiaJ81z8IDrBYcToAQAAAAD9////CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkAAAAAAP3///8BkF8BAAAAAAAiACADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAAG/ANxc2IAC3Byb3ByaWV0YXJ5AAEAXAIAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAAAP3///8CiBMAAAAAAAABUaCGAQAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOIAAAAAAQEfoIYBAAAAAAAWABTAzrzWw9PKjHXcXsYuvlUzDvkQ4gABAQoHAAAAAAAAAAFRAvABB3Vua25vd24AAfEUdW5rbm93biBvdXRwdXQgZmllbGQA";

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

fn key_bytes(hex_value: &str) -> [u8; 32] {
    hex::decode(hex_value).unwrap().try_into().unwrap()
}

#[wasm_bindgen_test]
fn derives_the_bip84_vector() {
    let keypair = derive_bitcoin_p2wpkh_keypair(BIP84_MNEMONIC, 0, 0, 0, None).unwrap();
    assert_eq!(keypair.private_key, BIP84_KEY);
    assert_eq!(
        keypair.public_key,
        "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
    );
    assert_eq!(
        keypair.address,
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );
    assert_eq!(keypair.path, "m/84'/0'/0'/0/0");
    assert!(!format!("{keypair:?}").contains(BIP84_KEY));
}

#[wasm_bindgen_test]
fn derivation_refuses_a_change_index_other_than_zero_or_one() {
    let error = derive_bitcoin_p2wpkh_keypair(BIP84_MNEMONIC, 0, 2, 0, None).unwrap_err();
    assert!(js_error_message(error).contains("change 2"));
}

#[wasm_bindgen_test]
fn signs_the_bip322_vector() {
    // The low-R "Hello World" signature from the BIP-322 vectors.
    assert_eq!(
        sign_bip322_simple(BIP322_KEY, BIP322_ADDRESS, "Hello World").unwrap(),
        "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
    );
    let error = sign_bip322_simple(BIP84_KEY, BIP322_ADDRESS, "Hello World").unwrap_err();
    assert!(js_error_message(error).starts_with("BIP-322 signing failed:"));
}

#[wasm_bindgen_test]
fn signs_listed_psbt_inputs_like_the_core_crate() {
    let signed = sign_bitcoin_psbt_inputs(BIP84_KEY, PSBT, vec![0]).unwrap();
    let core = krusty_kms::sign_bitcoin_psbt_inputs(&key_bytes(BIP84_KEY), PSBT, &[0]).unwrap();
    assert_eq!(signed, core);
    assert_ne!(signed, PSBT);

    let error = sign_bitcoin_psbt_inputs(BIP84_KEY, PSBT, vec![1]).unwrap_err();
    assert!(js_error_message(error).contains("PSBT input 1"));
    let error = sign_bitcoin_psbt_inputs(BIP84_KEY, "cHNidP8=", vec![0]).unwrap_err();
    assert!(js_error_message(error).starts_with("Bitcoin PSBT signing failed:"));
}

#[wasm_bindgen_test]
fn private_keys_are_parsed_strictly_and_never_echoed() {
    let prefixed = format!("0x{}", &BIP84_KEY[2..]);
    let short = &BIP84_KEY[..62];
    let not_hex = format!("{}zz", &BIP84_KEY[..62]);
    for bad in [prefixed.as_str(), short, not_hex.as_str(), ""] {
        let message = js_error_message(sign_bip322_simple(bad, BIP322_ADDRESS, "").unwrap_err());
        assert!(message.contains("64 hex chars"), "{message}");
        assert!(bad.is_empty() || !message.contains(bad));
    }
}
