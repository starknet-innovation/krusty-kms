//! Parsing of secret inputs into types that are wiped on drop.
//!
//! Callers hold the input string itself in `Zeroizing`; these parsers make no
//! further copy of it on the heap.

#[cfg(test)]
mod tests;

use krusty_kms_common::SecretFelt;
use starknet_types_core::felt::Felt;
use wasm_bindgen::JsValue;
use zeroize::Zeroizing;

/// Why a secret hex string was refused.
#[derive(Debug, PartialEq)]
pub(crate) enum SecretHexError {
    /// What `hex::decode` reports: an odd length or a non-hex character.
    Hex(hex::FromHexError),
    /// Valid hex that decodes to this many bytes instead of the expected count.
    Length(usize),
}

/// Decode exactly `N` bytes of hex into a buffer that is wiped on drop.
///
/// Refuses the same inputs, with the same errors in the same order, as
/// `hex::decode` followed by a length check, but never allocates:
/// `hex::decode` grows a `Vec` as it goes and frees each outgrown buffer
/// without wiping it.
pub(crate) fn decode_secret_hex<const N: usize>(
    hex_str: &str,
) -> Result<Zeroizing<[u8; N]>, SecretHexError> {
    let mut bytes = Zeroizing::new([0u8; N]);
    match hex::decode_to_slice(hex_str, bytes.as_mut_slice()) {
        Ok(()) => Ok(bytes),
        // `decode_to_slice` checks the length before the characters;
        // `hex::decode` reports the first bad character instead.
        Err(hex::FromHexError::InvalidStringLength) => Err(
            match hex_str.bytes().position(|byte| !byte.is_ascii_hexdigit()) {
                Some(index) => SecretHexError::Hex(hex::FromHexError::InvalidHexCharacter {
                    c: char::from(hex_str.as_bytes()[index]),
                    index,
                }),
                None => SecretHexError::Length(hex_str.len() / 2),
            },
        ),
        Err(error) => Err(SecretHexError::Hex(error)),
    }
}

/// Parse a hex felt (reduced, as `Felt::from_hex` does) into a [`SecretFelt`].
///
/// A refusal is reported as `"{context}: {error}"`; the error never contains
/// the input.
pub(crate) fn parse_secret_felt(hex_str: &str, context: &str) -> Result<SecretFelt, JsValue> {
    Felt::from_hex(hex_str)
        .map(SecretFelt::new)
        .map_err(|error| JsValue::from_str(&format!("{context}: {error}")))
}
