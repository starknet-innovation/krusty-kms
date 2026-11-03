//! Strict parser for the BIP's `T`.
//!
//! `T` is the legacy serialization of the spending transaction with every
//! scriptSig emptied and the witness omitted. After disclosure only this exact
//! `T` may be retried, so a `T` that can never confirm would strand the vault.
//! Besides the encoding itself, the parser therefore applies Bitcoin's
//! context-free transaction rules (`CheckTransaction`): at least one input and
//! one output, no duplicate or null outpoints, and output values within
//! `MAX_MONEY`. Its size is capped at `QSB_MAX_TRANSACTION_SIZE` before
//! parsing, and once parsed `T` must leave room, input by input, for the
//! unlocking data the real spend adds (see `MAX_UNLOCKING_WEIGHT_PER_INPUT`).

#[cfg(test)]
mod tests;

use super::QSB_MAX_TRANSACTION_SIZE as MAX_TRANSACTION_SIZE;
use krusty_kms_common::{KmsError, Result};
use std::collections::BTreeSet;

/// 21 million BTC in satoshis.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
/// Bitcoin Core's standard transaction weight (`MAX_STANDARD_TX_WEIGHT`).
const MAX_STANDARD_TX_WEIGHT: usize = 400_000;
/// Weight units per non-witness byte (`WITNESS_SCALE_FACTOR`).
const WITNESS_SCALE_FACTOR: usize = 4;
/// Consensus limit on any script, scriptSigs included (`MAX_SCRIPT_SIZE`).
const MAX_SCRIPT_SIZE: usize = 10_000;
/// A `MAX_SCRIPT_SIZE` scriptSig's CompactSize length takes 3 bytes; `T` has 1.
const SCRIPT_SIG_LENGTH_GROWTH: usize = 3 - 1;
/// The largest P2WPKH witness, in bytes (1 WU each): the item count, then a
/// 73-byte DER signature with its sighash byte and a 33-byte compressed key,
/// each after a 1-byte length.
const MAX_P2WPKH_WITNESS: usize = 1 + (1 + 73) + (1 + 33);
/// The segwit marker and flag, added once when any input has a witness.
const SEGWIT_MARKER_AND_FLAG: usize = 2;
/// The most weight signing can add to one input of `T`, without knowing which
/// inputs are vaults: a full legacy scriptSig (`MAX_SCRIPT_SIZE` bytes plus
/// its longer length prefix, at `WITNESS_SCALE_FACTOR` WU per byte) and a
/// P2WPKH witness, the two input kinds a QSB withdrawal signs. That is
/// 4 × (10,000 + 2) + 109 = 40,117 WU. Other witness types are not budgeted.
const MAX_UNLOCKING_WEIGHT_PER_INPUT: usize =
    WITNESS_SCALE_FACTOR * (MAX_SCRIPT_SIZE + SCRIPT_SIG_LENGTH_GROWTH) + MAX_P2WPKH_WITNESS;

fn malformed(reason: impl core::fmt::Display) -> KmsError {
    KmsError::DeserializationError(format!("QSB transaction: {reason}"))
}

/// Accept `bytes` only if it is a complete, valid `T`.
pub(super) fn validate(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_TRANSACTION_SIZE {
        return Err(malformed(format!(
            "{} bytes exceeds the {MAX_TRANSACTION_SIZE}-byte limit",
            bytes.len()
        )));
    }
    let mut reader = Reader { bytes, at: 0 };
    reader.take(4, "version")?;
    // A legacy encoding cannot start its input list with 0x00: that byte is
    // either the segwit marker or an empty input list, and both are refused.
    if reader.bytes.get(reader.at) == Some(&0x00) {
        return Err(malformed(
            "segwit marker or empty input list; T must be legacy-serialized with at least one input",
        ));
    }
    let input_count = inputs(&mut reader)?;
    outputs(&mut reader)?;
    reader.take(4, "locktime")?;
    if reader.at != bytes.len() {
        return Err(malformed(format!(
            "{} trailing bytes after locktime",
            bytes.len() - reader.at
        )));
    }
    unlocking_budget(bytes.len(), input_count)
}

/// Refuse a `T` whose signed spend could exceed the standard weight, so that
/// fixing `T` at exposure can never strand the withdrawal.
fn unlocking_budget(len: usize, input_count: u64) -> Result<()> {
    let worst = usize::try_from(input_count)
        .ok()
        .and_then(|count| count.checked_mul(MAX_UNLOCKING_WEIGHT_PER_INPUT))
        .and_then(|unlocking| unlocking.checked_add(SEGWIT_MARKER_AND_FLAG))
        .and_then(|unlocking| unlocking.checked_add(WITNESS_SCALE_FACTOR * len));
    match worst {
        Some(weight) if weight <= MAX_STANDARD_TX_WEIGHT => Ok(()),
        _ => Err(malformed(format!(
            "T leaves no room for its inputs' unlocking data: {input_count} inputs \
             signed could weigh more than the {MAX_STANDARD_TX_WEIGHT} WU standard limit"
        ))),
    }
}

/// Parse the input list and return the number of inputs.
fn inputs(reader: &mut Reader<'_>) -> Result<u64> {
    let count = reader.compact_size("input count")?;
    let mut outpoints = BTreeSet::new();
    for input in 0..count {
        let outpoint: &[u8; 36] = reader.array("outpoint")?;
        // The coinbase outpoint: an all-zero txid with index 0xffffffff.
        if outpoint[..32] == [0; 32] && outpoint[32..] == [0xff; 4] {
            return Err(malformed(format!("input {input} spends the null outpoint")));
        }
        if !outpoints.insert(outpoint) {
            return Err(malformed(format!("input {input} repeats an outpoint")));
        }
        if reader.compact_size("scriptSig length")? != 0 {
            return Err(malformed(format!(
                "input {input} has a non-empty scriptSig; T requires every scriptSig empty"
            )));
        }
        reader.take(4, "sequence")?;
    }
    Ok(count)
}

fn outputs(reader: &mut Reader<'_>) -> Result<()> {
    let count = reader.compact_size("output count")?;
    if count == 0 {
        return Err(malformed("no outputs"));
    }
    let mut total = 0u64;
    for output in 0..count {
        // Read unsigned: a negative i64 amount lands above MAX_MONEY.
        let value = u64::from_le_bytes(*reader.array("output value")?);
        if value > MAX_MONEY {
            return Err(malformed(format!(
                "output {output} value exceeds MAX_MONEY"
            )));
        }
        // Both terms are at most MAX_MONEY here, so the sum cannot overflow.
        total += value;
        if total > MAX_MONEY {
            return Err(malformed("output values total more than MAX_MONEY"));
        }
        let script_len = reader.compact_size("scriptPubKey length")?;
        reader.take(script_len, "scriptPubKey")?;
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: u64, field: &str) -> Result<&'a [u8]> {
        let end = usize::try_from(len)
            .ok()
            .and_then(|len| self.at.checked_add(len))
            .filter(|&end| end <= self.bytes.len())
            .ok_or_else(|| malformed(format!("truncated {field} at byte {}", self.at)))?;
        let taken = &self.bytes[self.at..end];
        self.at = end;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self, field: &str) -> Result<&'a [u8; N]> {
        let taken = self.take(N as u64, field)?;
        Ok(taken.try_into().expect("take returns exactly N bytes"))
    }

    /// A Bitcoin CompactSize, refusing non-minimal encodings as Bitcoin does.
    fn compact_size(&mut self, field: &str) -> Result<u64> {
        let start = self.at;
        let (value, minimum) = match self.array::<1>(field)?[0] {
            0xfd => (u64::from(u16::from_le_bytes(*self.array(field)?)), 0xfd),
            0xfe => (u64::from(u32::from_le_bytes(*self.array(field)?)), 0x1_0000),
            0xff => (u64::from_le_bytes(*self.array(field)?), 0x1_0000_0000),
            small => return Ok(u64::from(small)),
        };
        if value < minimum {
            return Err(malformed(format!(
                "non-canonical {field} encoding at byte {start}"
            )));
        }
        Ok(value)
    }
}
