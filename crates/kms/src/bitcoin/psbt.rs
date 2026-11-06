//! BIP-174 (version 0) PSBT parsing and P2WPKH input signing.
//!
//! Every map is kept as its ordered key-value pairs, so serializing a parsed
//! PSBT reproduces it byte for byte. Signing only adds or replaces this key's
//! partial signature in the listed input maps.

mod fields;
mod input_rules;

use super::keys::P2wpkhSigner;
use super::tx::{
    malformed, write_compact_size, write_var_bytes, OutPoint, Reader, Transaction, TxOut,
    SIGHASH_ALL,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use fields::{check_pair, refused_on_listed_input};
use krusty_kms_common::{KmsError, Result};
use std::collections::BTreeSet;

const MAGIC: &[u8; 5] = b"psbt\xff";
/// Largest decoded PSBT accepted (4 MiB): room for ten maximum-size
/// standard previous transactions. Parsing keeps every pair in its own
/// allocation, so this bounds heap use as well as input size.
const MAX_PSBT_BYTES: usize = 4 * 1024 * 1024;

const GLOBAL_UNSIGNED_TX: u8 = 0x00;

const IN_NON_WITNESS_UTXO: u8 = 0x00;
const IN_WITNESS_UTXO: u8 = 0x01;
const IN_PARTIAL_SIG: u8 = 0x02;
const IN_SIGHASH_TYPE: u8 = 0x03;

// Types only the tests name; `fields::FIELDS` owns the rules for them.
#[cfg(test)]
const GLOBAL_VERSION: u8 = 0xfb;
#[cfg(test)]
const IN_REDEEM_SCRIPT: u8 = 0x04;
#[cfg(test)]
const IN_WITNESS_SCRIPT: u8 = 0x05;
#[cfg(test)]
const IN_FINAL_SCRIPTSIG: u8 = 0x07;
#[cfg(test)]
const IN_FINAL_SCRIPTWITNESS: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pair {
    key: Vec<u8>,
    value: Vec<u8>,
}

type Map = Vec<Pair>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        // `read_map` checks every pair against the BIP-174 field table,
        // including the version and the unsigned transaction's scriptSigs.
        let global = read_map(&mut reader, Scope::Global)?;
        let unsigned_tx = Transaction::parse_legacy(
            find(&global, GLOBAL_UNSIGNED_TX)
                .ok_or_else(|| malformed("PSBT has no unsigned transaction"))?,
        )?;
        let inputs = (0..unsigned_tx.inputs.len())
            .map(|_| read_map(&mut reader, Scope::Input))
            .collect::<Result<Vec<_>>>()?;
        for (index, (input, map)) in unsigned_tx.inputs.iter().zip(&inputs).enumerate() {
            require_spent_transaction(index, &input.previous_output, map)?;
            input_rules::require_declared_sighash(index, map)?;
        }
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
    sign_with(&P2wpkhSigner::new(private_key)?, psbt_base64, input_indices)
}

/// `sign_bitcoin_psbt_inputs` for a signer that is already set up.
fn sign_with(signer: &P2wpkhSigner, psbt_base64: &str, input_indices: &[u32]) -> Result<String> {
    let mut psbt = Psbt::parse(&decode_bounded(psbt_base64)?)?;

    let indices = checked_indices(input_indices, psbt.inputs.len())?;
    let midstate = psbt.unsigned_tx.sighash_midstate();
    for index in indices {
        let amount = signable_amount(&psbt, index, signer)?;
        let sighash =
            psbt.unsigned_tx
                .p2wpkh_sighash_all(&midstate, index, &signer.pubkey_hash, amount)?;
        let signature = signer.sign_sighash_all(&sighash)?;
        let map = psbt
            .inputs
            .get_mut(index)
            .ok_or_else(|| out_of_range(index))?;
        put_partial_signature(map, &signer.public_key, signature);
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

/// As Bitcoin Core does when it decodes a PSBT, refuse a `non_witness_utxo`
/// that is not the transaction its input spends, on any input.
fn require_spent_transaction(index: usize, outpoint: &OutPoint, map: &Map) -> Result<()> {
    let Some(bytes) = find(map, IN_NON_WITNESS_UTXO) else {
        return Ok(());
    };
    let previous_tx = Transaction::parse_network(bytes)?;
    if previous_tx.txid() != outpoint.txid {
        return Err(malformed(format!(
            "PSBT input {index}: non_witness_utxo is not the transaction this input spends"
        )));
    }
    if usize::try_from(outpoint.vout).map_or(true, |vout| vout >= previous_tx.outputs.len()) {
        return Err(malformed(format!(
            "PSBT input {index}: non_witness_utxo has no output at the spent index"
        )));
    }
    Ok(())
}

/// Check that input `index` is this key's P2WPKH spend and return its
/// amount, proven against the full previous transaction.
fn signable_amount(psbt: &Psbt, index: usize, signer: &P2wpkhSigner) -> Result<u64> {
    let map = psbt.inputs.get(index).ok_or_else(|| out_of_range(index))?;
    let refuse = |reason: &str| KmsError::TransactionError(format!("PSBT input {index}: {reason}"));

    // Fields the table marks as wrong for a plain P2WPKH SIGHASH_ALL spend:
    // finalized fields, and redeem or witness scripts (BIP-174 has signers
    // check those against the UTXO, and a native P2WPKH spend has neither).
    for pair in map {
        let key_type = Reader::new(&pair.key).compact_u64()?;
        if let Some(reason) = refused_on_listed_input(key_type) {
            return Err(refuse(reason));
        }
    }
    let sighash_all = u32::from(SIGHASH_ALL).to_le_bytes();
    if find(map, IN_SIGHASH_TYPE).is_some_and(|value| value != sighash_all) {
        return Err(refuse("requests a sighash type other than SIGHASH_ALL"));
    }
    if input_rules::has_partial_signature_other_than_all(map) {
        return Err(refuse("carries a partial signature other than SIGHASH_ALL"));
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
    // `Psbt::parse` proved this is the transaction the input spends.
    let outpoint = &psbt
        .unsigned_tx
        .inputs
        .get(index)
        .ok_or_else(|| out_of_range(index))?
        .previous_output;
    let spent = usize::try_from(outpoint.vout)
        .ok()
        .and_then(|vout| previous_tx.outputs.get(vout))
        .ok_or_else(|| refuse("non_witness_utxo has no output at the spent index"))?;
    if *spent != witness_utxo {
        return Err(refuse("witness_utxo does not match the output it spends"));
    }
    Ok(witness_utxo.value)
}

/// `checked_indices` already bounds every index; this keeps lookups checked.
fn out_of_range(index: usize) -> KmsError {
    KmsError::TransactionError(format!("PSBT input {index} is out of range"))
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

/// The value of the map's key of type `key_type` with no key data.
///
/// `read_map` refuses non-minimal key types, so for a type below 0xfd the
/// only encoding of that key is the single byte `[key_type]`.
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
        // BIP-174 key types are CompactSizes. Reading them minimally means
        // `fd 03 00` cannot pose as an unknown type 0xfd that hides a sighash
        // type, a finalized field, or a duplicate of `03`.
        let mut key_reader = Reader::new(key);
        let key_type = key_reader.compact_u64()?;
        let key_data = key_reader.rest();
        if !keys.insert((key_type, key_data)) {
            return Err(malformed("PSBT map repeats a key"));
        }
        let value = reader.var_bytes()?;
        check_pair(scope, key_type, key_data, value)?;
        map.push(Pair {
            key: key.to_vec(),
            value: value.to_vec(),
        });
    }
}

#[cfg(test)]
mod fields_test;
#[cfg(test)]
mod key_encoding_test;
#[cfg(test)]
mod no_panic_test;
#[cfg(test)]
mod partial_sig_test;
#[cfg(test)]
mod scaling_test;
#[cfg(test)]
mod tests;
