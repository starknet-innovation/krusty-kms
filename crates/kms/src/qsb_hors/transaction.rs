//! Strict parser for the BIP's `T`.
//!
//! `T` is the legacy serialization of the spending transaction with every
//! scriptSig emptied and the witness omitted. After disclosure only this exact
//! `T` may be retried, so a `T` that can never confirm would strand the vault.
//! Besides the encoding itself, the parser therefore applies Bitcoin's
//! context-free transaction rules (`CheckTransaction`): at least one input and
//! one output, no duplicate or null outpoints, output values within
//! `MAX_MONEY`, and a size within the block limit.

use krusty_kms_common::{KmsError, Result};
use std::collections::BTreeSet;

/// 21 million BTC in satoshis.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
/// `MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR`: the largest stripped size a
/// transaction can have. Adding scriptSigs only makes it larger.
const MAX_TRANSACTION_SIZE: usize = 1_000_000;

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
    inputs(&mut reader)?;
    outputs(&mut reader)?;
    reader.take(4, "locktime")?;
    if reader.at != bytes.len() {
        return Err(malformed(format!(
            "{} trailing bytes after locktime",
            bytes.len() - reader.at
        )));
    }
    Ok(())
}

fn inputs(reader: &mut Reader<'_>) -> Result<()> {
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
    Ok(())
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
