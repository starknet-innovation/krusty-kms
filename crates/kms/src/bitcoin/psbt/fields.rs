//! The BIP-174 version-0 field table: for every field BIP-174 defines, the
//! key data and value it requires, and whether a listed native P2WPKH input
//! may carry it. Each pair is checked against it as it is read, in every map,
//! so a malformed PSBT is refused before anything is signed.
//!
//! Types the table does not name (later BIPs such as Taproot's, and unknown
//! types) pass through as opaque once their key type has been read. Types
//! that only exist in PSBT version 2 (BIP-370) are refused.

use super::super::tx::{double_sha256, malformed, Reader, Transaction, TxOut};
use super::Scope::{self, Global, Input, Output as Out};
use bitcoin_hashes::{hash160, ripemd160, Hash as _};
use krusty_kms_common::{KmsError, Result};
use sha2::{Digest, Sha256};

/// The key data a field requires after its type.
#[derive(Clone, Copy)]
enum KeyData {
    None,
    Hash(usize),
    PublicKey,
    /// A 78-byte BIP-32 extended public key.
    ExtendedPublicKey,
    /// `<compact size identifier length> <identifier> <compact size subtype> <key data>`.
    Proprietary,
}

/// The value a field requires.
#[derive(Clone, Copy)]
enum Value {
    Any,
    /// Legacy serialization with every scriptSig empty.
    UnsignedTransaction,
    /// Network serialization, by Bitcoin Core's deserialization rules.
    Transaction,
    Output,
    /// A strict-DER ECDSA signature followed by a defined sighash type.
    Signature,
    U32,
    /// A 32-bit version that must be 0.
    Version,
    /// A 4-byte fingerprint followed by 4-byte path elements.
    KeyOrigin,
    /// A key origin with as many path elements as the extended key's depth.
    XpubKeyOrigin,
    /// A consensus-encoded witness stack.
    WitnessStack,
    Preimage(fn(&[u8]) -> Vec<u8>),
}

/// What a listed native P2WPKH input may carry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OnListedInput {
    Allowed,
    /// Present means the input is not a plain P2WPKH SIGHASH_ALL spend.
    Refused(&'static str),
}

struct Field {
    scope: Scope,
    key_type: u64,
    name: &'static str,
    key: KeyData,
    value: Value,
    on_listed_input: OnListedInput,
}

const fn f(scope: Scope, key_type: u64, name: &'static str, key: KeyData, value: Value) -> Field {
    Field {
        scope,
        key_type,
        name,
        key,
        value,
        on_listed_input: OnListedInput::Allowed,
    }
}

const fn refused(mut field: Field, reason: &'static str) -> Field {
    field.on_listed_input = OnListedInput::Refused(reason);
    field
}

const REDEEM_SCRIPT: &str = "carries a redeem script, which a native P2WPKH input cannot use";
const WITNESS_SCRIPT: &str = "carries a witness script, which a native P2WPKH input cannot use";
const FINALIZED: &str = "is already finalized";

use KeyData as K;
use Value as V;

/// Every PSBTv0 field BIP-174 defines. A SIGHASH_TYPE on a listed input must
/// also be SIGHASH_ALL; the signer checks that value itself. One row per
/// field, so the table reads like BIP-174's.
#[rustfmt::skip]
const FIELDS: [Field; 22] = [
    f(Global, 0x00, "PSBT_GLOBAL_UNSIGNED_TX", K::None, V::UnsignedTransaction),
    f(Global, 0x01, "PSBT_GLOBAL_XPUB", K::ExtendedPublicKey, V::XpubKeyOrigin),
    f(Global, 0xfb, "PSBT_GLOBAL_VERSION", K::None, V::Version),
    f(Global, 0xfc, "PSBT_GLOBAL_PROPRIETARY", K::Proprietary, V::Any),
    f(Input, 0x00, "PSBT_IN_NON_WITNESS_UTXO", K::None, V::Transaction),
    f(Input, 0x01, "PSBT_IN_WITNESS_UTXO", K::None, V::Output),
    f(Input, 0x02, "PSBT_IN_PARTIAL_SIG", K::PublicKey, V::Signature),
    f(Input, 0x03, "PSBT_IN_SIGHASH_TYPE", K::None, V::U32),
    refused(f(Input, 0x04, "PSBT_IN_REDEEM_SCRIPT", K::None, V::Any), REDEEM_SCRIPT),
    refused(f(Input, 0x05, "PSBT_IN_WITNESS_SCRIPT", K::None, V::Any), WITNESS_SCRIPT),
    f(Input, 0x06, "PSBT_IN_BIP32_DERIVATION", K::PublicKey, V::KeyOrigin),
    refused(f(Input, 0x07, "PSBT_IN_FINAL_SCRIPTSIG", K::None, V::Any), FINALIZED),
    refused(f(Input, 0x08, "PSBT_IN_FINAL_SCRIPTWITNESS", K::None, V::WitnessStack), FINALIZED),
    f(Input, 0x0a, "PSBT_IN_RIPEMD160", K::Hash(20), V::Preimage(ripemd160_of)),
    f(Input, 0x0b, "PSBT_IN_SHA256", K::Hash(32), V::Preimage(sha256_of)),
    f(Input, 0x0c, "PSBT_IN_HASH160", K::Hash(20), V::Preimage(hash160_of)),
    f(Input, 0x0d, "PSBT_IN_HASH256", K::Hash(32), V::Preimage(hash256_of)),
    f(Input, 0xfc, "PSBT_IN_PROPRIETARY", K::Proprietary, V::Any),
    f(Out, 0x00, "PSBT_OUT_REDEEM_SCRIPT", K::None, V::Any),
    f(Out, 0x01, "PSBT_OUT_WITNESS_SCRIPT", K::None, V::Any),
    f(Out, 0x02, "PSBT_OUT_BIP32_DERIVATION", K::PublicKey, V::KeyOrigin),
    f(Out, 0xfc, "PSBT_OUT_PROPRIETARY", K::Proprietary, V::Any),
];

/// Whether `key_type` in `scope` only exists in PSBT version 2 (BIP-370).
fn is_version_2_only(scope: Scope, key_type: u64) -> bool {
    match scope {
        Global => (0x02..=0x06).contains(&key_type),
        Input => (0x0e..=0x12).contains(&key_type),
        Out => (0x03..=0x04).contains(&key_type),
    }
}

/// Check one pair against the table: version-2 fields are refused, a known
/// field's key data and value must have the shape BIP-174 defines, and an
/// unknown field passes through.
pub(super) fn check_pair(scope: Scope, key_type: u64, key_data: &[u8], value: &[u8]) -> Result<()> {
    if is_version_2_only(scope, key_type) {
        return Err(malformed(format!(
            "PSBT key type {key_type:#04x} is a PSBT version 2 field, not allowed in version 0"
        )));
    }
    let Some(field) = lookup(scope, key_type) else {
        return Ok(());
    };
    if !key_is_valid(field.key, key_data) {
        return Err(malformed(format!("{} has an invalid key", field.name)));
    }
    check_value(field, key_data, value)
}

/// The reason a listed P2WPKH input may not carry a field of `key_type`.
pub(super) fn refused_on_listed_input(key_type: u64) -> Option<&'static str> {
    match lookup(Input, key_type)?.on_listed_input {
        OnListedInput::Refused(reason) => Some(reason),
        OnListedInput::Allowed => None,
    }
}

fn lookup(scope: Scope, key_type: u64) -> Option<&'static Field> {
    FIELDS
        .iter()
        .find(|field| field.scope == scope && field.key_type == key_type)
}

fn key_is_valid(key: KeyData, key_data: &[u8]) -> bool {
    match key {
        KeyData::None => key_data.is_empty(),
        KeyData::Hash(len) => key_data.len() == len,
        KeyData::PublicKey => is_public_key(key_data),
        // version(4) depth(1) parent fingerprint(4) child(4) chain code(32) key(33).
        KeyData::ExtendedPublicKey => {
            key_data.len() == 78
                && key_data.get(45..).is_some_and(|public_key| {
                    matches!(public_key.first(), Some(0x02 | 0x03)) && is_public_key(public_key)
                })
        }
        KeyData::Proprietary => is_proprietary_key(key_data),
    }
}

fn check_value(field: &Field, key_data: &[u8], value: &[u8]) -> Result<()> {
    let valid = match field.value {
        Value::Any => true,
        Value::UnsignedTransaction => {
            let tx = within(field, Transaction::parse_legacy(value))?;
            if tx.inputs.iter().any(|input| !input.script_sig.is_empty()) {
                return Err(malformed("unsigned transaction has a scriptSig"));
            }
            true
        }
        Value::Transaction => within(field, Transaction::parse_network(value)).map(|_| true)?,
        Value::Output => within(field, TxOut::parse_exact(value)).map(|_| true)?,
        Value::Signature => is_signature(value),
        Value::U32 => value.len() == 4,
        Value::Version => {
            if value.len() == 4 && value != [0, 0, 0, 0] {
                return Err(malformed("only PSBT version 0 is supported"));
            }
            value.len() == 4
        }
        Value::KeyOrigin => is_key_origin(value),
        // BIP-174: the number of path elements must match the depth byte of
        // the 78-byte extended key.
        Value::XpubKeyOrigin => {
            is_key_origin(value)
                && key_data.get(4).is_some_and(|depth| {
                    (value.len() / 4).checked_sub(1) == Some(usize::from(*depth))
                })
        }
        Value::WitnessStack => is_witness_stack(value),
        Value::Preimage(hash) => {
            if hash(value) != key_data {
                return Err(malformed(format!(
                    "{} preimage does not hash to its key",
                    field.name
                )));
            }
            true
        }
    };
    if valid {
        Ok(())
    } else {
        Err(malformed(format!("{} has a malformed value", field.name)))
    }
}

/// Name the field in a parse error of its value.
fn within<T>(field: &Field, parsed: Result<T>) -> Result<T> {
    parsed.map_err(|error| match error {
        KmsError::DeserializationError(reason) => {
            KmsError::DeserializationError(format!("{reason} in {}", field.name))
        }
        other => other,
    })
}

/// A 4-byte fingerprint followed by whole 4-byte path elements.
fn is_key_origin(value: &[u8]) -> bool {
    !value.is_empty() && value.len().is_multiple_of(4)
}

/// A SEC1 public key, compressed or not, that is a point on secp256k1.
fn is_public_key(bytes: &[u8]) -> bool {
    let shaped = match bytes {
        [0x02 | 0x03, rest @ ..] => rest.len() == 32,
        [0x04, rest @ ..] => rest.len() == 64,
        _ => false,
    };
    shaped && k256::PublicKey::from_sec1_bytes(bytes).is_ok()
}

fn is_proprietary_key(key_data: &[u8]) -> bool {
    read_proprietary_key(&mut Reader::new(key_data)).is_ok()
}

/// Identifier length and identifier, then the subtype; the rest is opaque.
fn read_proprietary_key(reader: &mut Reader<'_>) -> Result<u64> {
    let identifier_len = reader.compact_size()?;
    reader.take(identifier_len)?;
    reader.compact_u64()
}

fn is_witness_stack(value: &[u8]) -> bool {
    read_witness_stack(&mut Reader::new(value)).is_ok()
}

fn read_witness_stack(reader: &mut Reader<'_>) -> Result<()> {
    for _ in 0..reader.compact_size()? {
        reader.var_bytes()?;
    }
    reader.finish()
}

/// Bitcoin Core's `CheckSignatureEncoding` with DERSIG and STRICTENC: strict
/// DER (BIP-66) followed by a defined sighash type.
fn is_signature(sig: &[u8]) -> bool {
    let Some((&sighash_type, der)) = sig.split_last() else {
        return false;
    };
    matches!(sighash_type & !0x80, 0x01..=0x03) && is_strict_der(der)
}

/// BIP-66 `IsValidSignatureEncoding` on the DER part:
/// `30 <len> 02 <len R> <R> 02 <len S> <S>`, 8 to 72 bytes, each integer
/// non-empty, non-negative and without a needless leading zero. Parsed with
/// checked splits only, so no length byte can index past the end.
fn is_strict_der(der: &[u8]) -> bool {
    let [0x30, len, body @ ..] = der else {
        return false;
    };
    if !(8..=72).contains(&der.len()) || usize::from(*len) != body.len() {
        return false;
    }
    let Some((r, rest)) = der_integer(body) else {
        return false;
    };
    let Some((s, rest)) = der_integer(rest) else {
        return false;
    };
    rest.is_empty() && is_minimal_positive(r) && is_minimal_positive(s)
}

/// Split `02 <len> <len bytes>` off the front.
fn der_integer(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let [0x02, len, rest @ ..] = bytes else {
        return None;
    };
    rest.split_at_checked(usize::from(*len))
}

fn is_minimal_positive(integer: &[u8]) -> bool {
    match integer {
        [] => false,
        [first, ..] if first & 0x80 != 0 => false,
        [0x00, second, ..] => second & 0x80 != 0,
        _ => true,
    }
}

fn ripemd160_of(value: &[u8]) -> Vec<u8> {
    ripemd160::Hash::hash(value).to_byte_array().to_vec()
}

fn sha256_of(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}

fn hash160_of(value: &[u8]) -> Vec<u8> {
    hash160::Hash::hash(value).to_byte_array().to_vec()
}

fn hash256_of(value: &[u8]) -> Vec<u8> {
    double_sha256(value).to_vec()
}
