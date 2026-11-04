//! `decode_secret_hex` is `hex::decode` plus a length check, without the `Vec`.

use super::*;
use wasm_bindgen_test::*;

/// The behavior being replaced: decode into a `Vec`, then check its length.
fn oracle<const N: usize>(hex_str: &str) -> Result<[u8; N], SecretHexError> {
    let bytes = hex::decode(hex_str).map_err(SecretHexError::Hex)?;
    let length = bytes.len();
    bytes.try_into().map_err(|_| SecretHexError::Length(length))
}

fn same_as_oracle<const N: usize>(hex_str: &str) {
    let decoded = decode_secret_hex::<N>(hex_str).map(|bytes| *bytes);
    assert_eq!(decoded, oracle::<N>(hex_str), "{hex_str:?}");
}

#[wasm_bindgen_test]
fn agrees_with_hex_decode_and_a_length_check() {
    let key = "B7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfeF";
    let mut inputs = vec![
        String::new(),
        "0x".to_string(),
        key.to_string(),
        format!("0x{key}"),
        format!("{key}00"),
        format!("é{}", &key[..62]),
        format!("é{key}"),
        format!(" {}", &key[1..]),
    ];
    // Every prefix, and every one-character corruption of the key and of a
    // key one byte short.
    inputs.extend((0..key.len()).map(|end| key[..end].to_string()));
    for source in [key, &key[..62]] {
        for index in 0..source.len() {
            for replacement in ["g", "-", "\u{0}"] {
                let (head, tail) = (&source[..index], &source[index + 1..]);
                inputs.push(format!("{head}{replacement}{tail}"));
            }
        }
    }
    for input in &inputs {
        same_as_oracle::<32>(input);
        same_as_oracle::<16>(input);
        same_as_oracle::<0>(input);
    }
}

#[wasm_bindgen_test]
fn reports_the_first_bad_character_before_a_bad_length() {
    assert_eq!(
        decode_secret_hex::<32>("0z1").map(|bytes| *bytes),
        Err(SecretHexError::Hex(hex::FromHexError::OddLength)),
    );
    assert_eq!(
        decode_secret_hex::<32>("00z1").map(|bytes| *bytes),
        Err(SecretHexError::Hex(
            hex::FromHexError::InvalidHexCharacter { c: 'z', index: 2 }
        )),
    );
    assert_eq!(
        decode_secret_hex::<32>("0011").map(|bytes| *bytes),
        Err(SecretHexError::Length(2)),
    );
}
