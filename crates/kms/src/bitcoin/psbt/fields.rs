//! BIP-174 rules for the fields of a version-0 PSBT map, checked as each pair
//! is read: the key shape every type BIP-174 defines requires, and preimage
//! values that must hash to their key.

use super::super::tx::{double_sha256, malformed};
use super::Scope;
use bitcoin_hashes::{hash160, ripemd160, Hash as _};
use krusty_kms_common::Result;
use sha2::{Digest, Sha256};

/// Refuse a key whose shape differs from the one BIP-174 defines for its
/// type (every type BIP-174 itself defines, except proprietary keys), and
/// fields that only exist in PSBT version 2 (BIP-370). Types from later BIPs,
/// such as Taproot's, and unknown types are opaque.
pub(super) fn require_key_shape(scope: Scope, key_type: u64, key_data: &[u8]) -> Result<()> {
    let none = key_data.is_empty();
    let valid = match (scope, key_type) {
        // Unsigned transaction, version; xpub keyed by a 78-byte extended key.
        (Scope::Global, 0x00 | 0xfb) => none,
        (Scope::Global, 0x01) => key_data.len() == 78,
        (Scope::Global, 0x02..=0x06) => false,
        (Scope::Input, 0x00 | 0x01 | 0x03 | 0x04 | 0x05 | 0x07 | 0x08) => none,
        (Scope::Input, 0x02 | 0x06) => is_public_key(key_data),
        // RIPEMD160 and HASH160 preimages are keyed by a 20-byte hash,
        // SHA256 and HASH256 preimages by a 32-byte hash.
        (Scope::Input, 0x0a | 0x0c) => key_data.len() == 20,
        (Scope::Input, 0x0b | 0x0d) => key_data.len() == 32,
        (Scope::Input, 0x0e..=0x12) => false,
        (Scope::Output, 0x00 | 0x01) => none,
        (Scope::Output, 0x02) => is_public_key(key_data),
        (Scope::Output, 0x03 | 0x04) => false,
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(malformed(format!(
            "PSBT key type {key_type:#04x} has an invalid key or is not allowed in version 0"
        )))
    }
}

/// Refuse a hash-preimage field whose value does not hash to its key, as
/// BIP-174 requires, in every input map, listed for signing or not.
pub(super) fn require_preimage(
    scope: Scope,
    key_type: u64,
    key_data: &[u8],
    value: &[u8],
) -> Result<()> {
    let matches = match (scope, key_type) {
        (Scope::Input, 0x0a) => ripemd160::Hash::hash(value).as_byte_array() == key_data,
        (Scope::Input, 0x0b) => Sha256::digest(value).as_slice() == key_data,
        (Scope::Input, 0x0c) => hash160::Hash::hash(value).as_byte_array() == key_data,
        (Scope::Input, 0x0d) => double_sha256(value) == key_data,
        _ => true,
    };
    if matches {
        Ok(())
    } else {
        Err(malformed(format!(
            "PSBT preimage of type {key_type:#04x} does not hash to its key"
        )))
    }
}

/// Whether `bytes` has the shape of a SEC1 public key (compressed or not).
fn is_public_key(bytes: &[u8]) -> bool {
    match bytes {
        [0x02 | 0x03, rest @ ..] => rest.len() == 32,
        [0x04, rest @ ..] => rest.len() == 64,
        _ => false,
    }
}
