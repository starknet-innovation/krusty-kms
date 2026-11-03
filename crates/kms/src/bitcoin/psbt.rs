//! BIP-174 (version 0) PSBT parsing and P2WPKH input signing.
//!
//! Every map is kept as its ordered key-value pairs, so serializing a parsed
//! PSBT reproduces it byte for byte. Signing only adds or replaces this key's
//! partial signature in the listed input maps.

use super::keys::P2wpkhSigner;
use super::tx::{
    malformed, write_compact_size, write_var_bytes, Reader, Transaction, TxOut, SIGHASH_ALL,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use krusty_kms_common::{KmsError, Result};
use std::collections::BTreeSet;

const MAGIC: &[u8; 5] = b"psbt\xff";
/// Largest decoded PSBT accepted (4 MiB): room for ten maximum-size
/// standard previous transactions. Parsing keeps every pair in its own
/// allocation, so this bounds heap use as well as input size.
const MAX_PSBT_BYTES: usize = 4 * 1024 * 1024;

const GLOBAL_UNSIGNED_TX: u8 = 0x00;
const GLOBAL_XPUB: u8 = 0x01;
const GLOBAL_VERSION: u8 = 0xfb;

const IN_NON_WITNESS_UTXO: u8 = 0x00;
const IN_WITNESS_UTXO: u8 = 0x01;
const IN_PARTIAL_SIG: u8 = 0x02;
const IN_SIGHASH_TYPE: u8 = 0x03;
const IN_FINAL_SCRIPTSIG: u8 = 0x07;
const IN_FINAL_SCRIPTWITNESS: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pair {
    key: Vec<u8>,
    value: Vec<u8>,
}

type Map = Vec<Pair>;

#[derive(Clone, Copy)]
enum Scope {
    Global,
    Input,
    Output,
}

/// A parsed version-0 PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Psbt {
    global: Map,
    unsigned_tx: Transaction,
    inputs: Vec<Map>,
    outputs: Vec<Map>,
}

impl Psbt {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(malformed("missing PSBT magic bytes"));
        }
        let global = read_map(&mut reader, Scope::Global)?;
        require_version_zero(&global)?;
        let unsigned_tx = Transaction::parse_legacy(
            find(&global, GLOBAL_UNSIGNED_TX)
                .ok_or_else(|| malformed("PSBT has no unsigned transaction"))?,
        )?;
        if unsigned_tx
            .inputs
            .iter()
            .any(|input| !input.script_sig.is_empty())
        {
            return Err(malformed("unsigned transaction has a scriptSig"));
        }
        let inputs = (0..unsigned_tx.inputs.len())
            .map(|_| read_map(&mut reader, Scope::Input))
            .collect::<Result<Vec<_>>>()?;
        let outputs = (0..unsigned_tx.outputs.len())
            .map(|_| read_map(&mut reader, Scope::Output))
            .collect::<Result<Vec<_>>>()?;
        reader.finish()?;
        Ok(Self {
            global,
            unsigned_tx,
            inputs,
            outputs,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for map in std::iter::once(&self.global)
            .chain(&self.inputs)
            .chain(&self.outputs)
        {
            for pair in map {
                write_var_bytes(&mut out, &pair.key);
                write_var_bytes(&mut out, &pair.value);
            }
            write_compact_size(&mut out, 0);
        }
        out
    }
}

/// Add this key's SIGHASH_ALL partial signature to each listed P2WPKH input
/// of a base64 version-0 PSBT, and return the PSBT as base64.
///
/// Each listed input must carry a `witness_utxo` paying this key's P2WPKH
/// script, a `non_witness_utxo` whose txid is the input's previous txid and
/// whose spent output equals the `witness_utxo`, and no sighash type other
/// than SIGHASH_ALL. Unlisted inputs, outputs and global fields are left
/// byte-identical. Nothing is finalized or broadcast.
///
/// # Errors
///
/// - `InvalidPrivateKey` when the key is not a valid secp256k1 scalar
/// - `DeserializationError` when the base64 or the PSBT is malformed, or the
///   PSBT is larger than 4 MiB
/// - `TransactionError` when the index list is empty, repeats or overruns,
///   or a listed input fails a check above; nothing is signed then
pub fn sign_bitcoin_psbt_inputs(
    private_key: &[u8; 32],
    psbt_base64: &str,
    input_indices: &[u32],
) -> Result<String> {
    let signer = P2wpkhSigner::new(private_key)?;
    let mut psbt = Psbt::parse(&decode_bounded(psbt_base64)?)?;

    for index in checked_indices(input_indices, psbt.inputs.len())? {
        let amount = signable_amount(&psbt, index, &signer)?;
        let sighash = psbt
            .unsigned_tx
            .p2wpkh_sighash_all(index, &signer.pubkey_hash, amount)?;
        let signature = signer.sign_sighash_all(&sighash)?;
        put_partial_signature(&mut psbt.inputs[index], &signer.public_key, signature);
    }
    Ok(BASE64.encode(psbt.serialize()))
}

/// Decode at most `MAX_PSBT_BYTES`, refusing longer text before decoding it.
fn decode_bounded(psbt_base64: &str) -> Result<Vec<u8>> {
    let too_large = || malformed(format!("PSBT is larger than {MAX_PSBT_BYTES} bytes"));
    // Base64 carries three bytes in every four characters.
    if psbt_base64.len() > MAX_PSBT_BYTES.div_ceil(3) * 4 {
        return Err(too_large());
    }
    let bytes = BASE64
        .decode(psbt_base64)
        .map_err(|e| malformed(format!("PSBT is not base64: {e}")))?;
    if bytes.len() > MAX_PSBT_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
}

fn checked_indices(indices: &[u32], input_count: usize) -> Result<Vec<usize>> {
    if indices.is_empty() {
        return Err(KmsError::TransactionError(
            "no PSBT inputs were listed to sign".into(),
        ));
    }
    // A longer list must repeat or overrun an index; refuse it before
    // allocating anything sized by it.
    if indices.len() > input_count {
        return Err(KmsError::TransactionError(format!(
            "{} PSBT inputs were listed but the PSBT has {input_count}",
            indices.len()
        )));
    }
    let mut seen = BTreeSet::new();
    let mut checked = Vec::with_capacity(indices.len());
    for &index in indices {
        let position = usize::try_from(index).unwrap_or(usize::MAX);
        if position >= input_count {
            return Err(KmsError::TransactionError(format!(
                "PSBT input {index} is out of range: the PSBT has {input_count} inputs"
            )));
        }
        if !seen.insert(position) {
            return Err(KmsError::TransactionError(format!(
                "PSBT input {index} is listed more than once"
            )));
        }
        checked.push(position);
    }
    Ok(checked)
}

/// Check that input `index` is this key's P2WPKH spend and return its
/// amount, proven against the full previous transaction.
fn signable_amount(psbt: &Psbt, index: usize, signer: &P2wpkhSigner) -> Result<u64> {
    let map = &psbt.inputs[index];
    let refuse = |reason: &str| KmsError::TransactionError(format!("PSBT input {index}: {reason}"));

    if find(map, IN_FINAL_SCRIPTSIG).is_some() || find(map, IN_FINAL_SCRIPTWITNESS).is_some() {
        return Err(refuse("is already finalized"));
    }
    let sighash_all = u32::from(SIGHASH_ALL).to_le_bytes();
    if find(map, IN_SIGHASH_TYPE).is_some_and(|value| value != sighash_all) {
        return Err(refuse("requests a sighash type other than SIGHASH_ALL"));
    }

    let witness_utxo = TxOut::parse_exact(
        find(map, IN_WITNESS_UTXO).ok_or_else(|| refuse("has no witness_utxo"))?,
    )?;
    if witness_utxo.script_pubkey != signer.script_pubkey() {
        return Err(refuse("witness_utxo is not this key's P2WPKH script"));
    }

    let previous_tx = Transaction::parse_network(
        find(map, IN_NON_WITNESS_UTXO).ok_or_else(|| refuse("has no non_witness_utxo"))?,
    )?;
    let outpoint = &psbt.unsigned_tx.inputs[index].previous_output;
    if previous_tx.txid() != outpoint.txid {
        return Err(refuse(
            "non_witness_utxo is not the transaction this input spends",
        ));
    }
    let spent = usize::try_from(outpoint.vout)
        .ok()
        .and_then(|vout| previous_tx.outputs.get(vout))
        .ok_or_else(|| refuse("non_witness_utxo has no output at the spent index"))?;
    if *spent != witness_utxo {
        return Err(refuse("witness_utxo does not match the output it spends"));
    }
    Ok(witness_utxo.value)
}

fn put_partial_signature(map: &mut Map, public_key: &[u8; 33], signature: Vec<u8>) {
    let mut key = Vec::with_capacity(1 + public_key.len());
    key.push(IN_PARTIAL_SIG);
    key.extend(public_key);
    match map.iter_mut().find(|pair| pair.key == key) {
        Some(pair) => pair.value = signature,
        None => map.push(Pair {
            key,
            value: signature,
        }),
    }
}

/// The value of the map's key that is exactly `[key_type]`.
fn find(map: &Map, key_type: u8) -> Option<&[u8]> {
    map.iter()
        .find(|pair| pair.key == [key_type])
        .map(|pair| pair.value.as_slice())
}

fn read_map(reader: &mut Reader<'_>, scope: Scope) -> Result<Map> {
    let mut map = Vec::new();
    let mut keys = BTreeSet::new();
    loop {
        let key = reader.var_bytes()?;
        if key.is_empty() {
            return Ok(map);
        }
        require_key_shape(scope, key)?;
        if !keys.insert(key) {
            return Err(malformed("PSBT map repeats a key"));
        }
        let value = reader.var_bytes()?;
        map.push(Pair {
            key: key.to_vec(),
            value: value.to_vec(),
        });
    }
}

/// Refuse a key whose shape differs from the one BIP-174 defines for its
/// type (every type BIP-174 itself defines, except proprietary keys), and
/// fields that only exist in PSBT version 2 (BIP-370). Types from later BIPs,
/// such as Taproot's, and unknown types are opaque.
fn require_key_shape(scope: Scope, key: &[u8]) -> Result<()> {
    let single = key.len() == 1;
    let valid = match (scope, key[0]) {
        (Scope::Global, GLOBAL_UNSIGNED_TX | GLOBAL_VERSION) => single,
        (Scope::Global, GLOBAL_XPUB) => key.len() == 1 + 78,
        (Scope::Global, 0x02..=0x06) => false,
        (Scope::Input, 0x00 | 0x01 | 0x03 | 0x04 | 0x05 | 0x07 | 0x08) => single,
        (Scope::Input, 0x02 | 0x06) => is_public_key(&key[1..]),
        // RIPEMD160 and HASH160 preimages are keyed by a 20-byte hash,
        // SHA256 and HASH256 preimages by a 32-byte hash.
        (Scope::Input, 0x0a | 0x0c) => key.len() == 1 + 20,
        (Scope::Input, 0x0b | 0x0d) => key.len() == 1 + 32,
        (Scope::Input, 0x0e..=0x12) => false,
        (Scope::Output, 0x00 | 0x01) => single,
        (Scope::Output, 0x02) => is_public_key(&key[1..]),
        (Scope::Output, 0x03 | 0x04) => false,
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(malformed(format!(
            "PSBT key type {:#04x} has an invalid key or is not allowed in version 0",
            key[0]
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

fn require_version_zero(global: &Map) -> Result<()> {
    match find(global, GLOBAL_VERSION) {
        None => Ok(()),
        Some(value) if value == [0, 0, 0, 0] => Ok(()),
        Some(_) => Err(malformed("only PSBT version 0 is supported")),
    }
}

#[cfg(test)]
mod tests;
