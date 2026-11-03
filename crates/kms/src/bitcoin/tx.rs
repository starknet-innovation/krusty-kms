//! Bitcoin transaction encoding, txids and the BIP-143 P2WPKH sighash.
//!
//! Parsing is strict: compact sizes must be minimal, lengths must fit the
//! remaining bytes, and no trailing bytes are allowed. That makes
//! `serialize(parse(bytes)) == bytes` for everything accepted, which the PSBT
//! signer relies on to leave unsigned inputs byte-identical.

use krusty_kms_common::{KmsError, Result};
use sha2::{Digest, Sha256};

/// The only sighash type this module signs.
pub(super) const SIGHASH_ALL: u8 = 0x01;

pub(super) fn malformed(what: impl core::fmt::Display) -> KmsError {
    KmsError::DeserializationError(format!("malformed bitcoin data: {what}"))
}

pub(super) fn double_sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// A bounds-checked cursor over untrusted bytes.
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.bytes.len() {
            return Err(malformed(format!(
                "needs {len} bytes, {} left",
                self.bytes.len()
            )));
        }
        let (head, tail) = self.bytes.split_at(len);
        self.bytes = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.bytes.starts_with(prefix)
    }

    /// Read a minimally encoded CompactSize and return it as a length.
    pub(super) fn compact_size(&mut self) -> Result<usize> {
        let (value, minimum) = match self.array::<1>()?[0] {
            0xfd => (u64::from(u16::from_le_bytes(self.array()?)), 0xfd),
            0xfe => (u64::from(u32::from_le_bytes(self.array()?)), 0x1_0000),
            0xff => (self.u64_le()?, 0x1_0000_0000),
            small => return Ok(usize::from(small)),
        };
        if value < minimum {
            return Err(malformed("non-canonical CompactSize"));
        }
        usize::try_from(value).map_err(|_| malformed("CompactSize does not fit in memory"))
    }

    /// Read a CompactSize length prefix and that many bytes.
    pub(super) fn var_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.compact_size()?;
        self.take(len)
    }

    pub(super) fn finish(&self) -> Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(malformed(format!("{} trailing bytes", self.bytes.len())))
        }
    }
}

pub(super) fn write_compact_size(out: &mut Vec<u8>, len: usize) {
    // usize -> u64 is lossless on every supported target.
    let value = len as u64;
    match value {
        0..=0xfc => out.push(value as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend((value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend((value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend(value.to_le_bytes());
        }
    }
}

pub(super) fn write_var_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// A previous output reference; `txid` is in internal (wire) byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OutPoint {
    pub(super) txid: [u8; 32],
    pub(super) vout: u32,
}

impl OutPoint {
    fn serialize_into(&self, out: &mut Vec<u8>) {
        out.extend(self.txid);
        out.extend(self.vout.to_le_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TxIn {
    pub(super) previous_output: OutPoint,
    pub(super) script_sig: Vec<u8>,
    pub(super) sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TxOut {
    pub(super) value: u64,
    pub(super) script_pubkey: Vec<u8>,
}

impl TxOut {
    fn parse(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            value: reader.u64_le()?,
            script_pubkey: reader.var_bytes()?.to_vec(),
        })
    }

    /// Parse a standalone output, as stored in a PSBT `witness_utxo`.
    pub(super) fn parse_exact(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let output = Self::parse(&mut reader)?;
        reader.finish()?;
        Ok(output)
    }

    pub(super) fn serialize_into(&self, out: &mut Vec<u8>) {
        out.extend(self.value.to_le_bytes());
        write_var_bytes(out, &self.script_pubkey);
    }
}

/// A transaction without its witness data, which no caller here needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Transaction {
    pub(super) version: u32,
    pub(super) inputs: Vec<TxIn>,
    pub(super) outputs: Vec<TxOut>,
    pub(super) lock_time: u32,
}

impl Transaction {
    /// Parse the legacy serialization, the only form BIP-174 allows for the
    /// unsigned transaction. A witness-serialized transaction is refused: its
    /// marker byte reads as an empty input list.
    pub(super) fn parse_legacy(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let version = reader.u32_le()?;
        let inputs = parse_inputs(&mut reader)?;
        let outputs = parse_outputs(&mut reader)?;
        let lock_time = reader.u32_le()?;
        reader.finish()?;
        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    /// Parse the network serialization, with or without segwit data.
    pub(super) fn parse_network(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let version = reader.u32_le()?;
        let segwit = reader.starts_with(&[0x00, 0x01]);
        if segwit {
            reader.take(2)?;
        }
        let inputs = parse_inputs(&mut reader)?;
        let outputs = parse_outputs(&mut reader)?;
        if segwit {
            for _ in &inputs {
                for _ in 0..reader.compact_size()? {
                    reader.var_bytes()?;
                }
            }
        }
        let lock_time = reader.u32_le()?;
        reader.finish()?;
        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    pub(super) fn serialize_legacy(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.version.to_le_bytes());
        write_compact_size(&mut out, self.inputs.len());
        for input in &self.inputs {
            input.previous_output.serialize_into(&mut out);
            write_var_bytes(&mut out, &input.script_sig);
            out.extend(input.sequence.to_le_bytes());
        }
        write_compact_size(&mut out, self.outputs.len());
        for output in &self.outputs {
            output.serialize_into(&mut out);
        }
        out.extend(self.lock_time.to_le_bytes());
        out
    }

    /// The txid in internal byte order (reverse of the usual hex display).
    pub(super) fn txid(&self) -> [u8; 32] {
        double_sha256(&self.serialize_legacy())
    }

    /// BIP-143 SIGHASH_ALL digest for input `index` spending a P2WPKH output
    /// of `amount` satoshis locked to `pubkey_hash`.
    pub(super) fn p2wpkh_sighash_all(
        &self,
        index: usize,
        pubkey_hash: &[u8; 20],
        amount: u64,
    ) -> Result<[u8; 32]> {
        let input = self
            .inputs
            .get(index)
            .ok_or_else(|| malformed(format!("no input {index} to sign")))?;
        let mut prevouts = Vec::new();
        let mut sequences = Vec::new();
        for each in &self.inputs {
            each.previous_output.serialize_into(&mut prevouts);
            sequences.extend(each.sequence.to_le_bytes());
        }
        let mut outputs = Vec::new();
        for output in &self.outputs {
            output.serialize_into(&mut outputs);
        }

        let mut preimage = Vec::with_capacity(182);
        preimage.extend(self.version.to_le_bytes());
        preimage.extend(double_sha256(&prevouts));
        preimage.extend(double_sha256(&sequences));
        input.previous_output.serialize_into(&mut preimage);
        // scriptCode for P2WPKH: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG.
        preimage.extend([0x19, 0x76, 0xa9, 0x14]);
        preimage.extend(pubkey_hash);
        preimage.extend([0x88, 0xac]);
        preimage.extend(amount.to_le_bytes());
        preimage.extend(input.sequence.to_le_bytes());
        preimage.extend(double_sha256(&outputs));
        preimage.extend(self.lock_time.to_le_bytes());
        preimage.extend(u32::from(SIGHASH_ALL).to_le_bytes());
        Ok(double_sha256(&preimage))
    }
}

fn parse_inputs(reader: &mut Reader<'_>) -> Result<Vec<TxIn>> {
    let count = reader.compact_size()?;
    if count == 0 {
        return Err(malformed("transaction has no inputs"));
    }
    let mut inputs = Vec::new();
    for _ in 0..count {
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: reader.array()?,
                vout: reader.u32_le()?,
            },
            script_sig: reader.var_bytes()?.to_vec(),
            sequence: reader.u32_le()?,
        });
    }
    Ok(inputs)
}

fn parse_outputs(reader: &mut Reader<'_>) -> Result<Vec<TxOut>> {
    let count = reader.compact_size()?;
    if count == 0 {
        return Err(malformed("transaction has no outputs"));
    }
    let mut outputs = Vec::new();
    for _ in 0..count {
        outputs.push(TxOut::parse(reader)?);
    }
    Ok(outputs)
}
