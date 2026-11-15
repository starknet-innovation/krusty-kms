// Portions ported from fireblocks-labs/pqb, Copyright (c) 2026 Fireblocks Ltd.
// MIT license: ../../licenses/PQB-MIT.txt (included in this crate package).
//! Validated selection, transaction binding and selective disclosure.
use super::{invalid, lock, PqbVault, Result};
use crate::bitcoin::tx::{double_sha256, Transaction};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Exactly 8 and 9 distinct, disjoint table indices and three bounded menu picks.
/// Ordering is preserved and included in the disclosure digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqbSelection {
    round0: [u8; 8],
    round1: [u8; 9],
    menus: [u8; 3],
}
impl PqbSelection {
    /// Validate selections and pin/round0/round1 menu indices (12/16/16 entries).
    pub fn new(round0: [u8; 8], round1: [u8; 9], menus: [u8; 3]) -> Result<Self> {
        let mut used = BTreeSet::new();
        for index in round0.iter().chain(&round1) {
            if *index >= 109 || !used.insert(*index) {
                return Err(invalid(
                    "HORS indices must be distinct across rounds and below 109",
                ));
            }
        }
        if menus.iter().zip([12, 16, 16]).any(|(i, n)| *i >= n) {
            return Err(invalid("menu index out of range"));
        }
        Ok(Self {
            round0,
            round1,
            menus,
        })
    }
    /// Ordered round-0 and round-1 selections.
    pub fn rounds(&self) -> (&[u8; 8], &[u8; 9]) {
        (&self.round0, &self.round1)
    }
    /// Menu choices in pin, round0, round1 order.
    pub fn menus(&self) -> &[u8; 3] {
        &self.menus
    }
}

/// Opaque, structurally validated authorization request. Persist `digest` before
/// disclosure. This is not a proof of funding, puzzle correctness or consensus.
#[derive(Debug)]
pub struct PqbRequest {
    script_hash: [u8; 32],
    selection: PqbSelection,
    digest: [u8; 32],
    cosig_hash: [u8; 32],
    stage_hashes: [[u8; 32]; 3],
}
impl PqbRequest {
    /// Domain-separated journal digest, binding the full unsigned transaction,
    /// lock, input index, ordered HORS choices and menu choices.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Full-lock legacy SIGHASH_ALL digest used by the co-signature.
    pub fn cosig_sighash(&self) -> [u8; 32] {
        self.cosig_hash
    }
    /// Pinning and two post-FindAndDelete round SIGHASH_ALL digests.
    pub fn stage_sighashes(&self) -> &[[u8; 32]; 3] {
        &self.stage_hashes
    }
}

/// Only the selected witness material and transaction co-signature. Wiped on
/// drop, Debug-redacted, and deliberately not serializable or cloneable.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PqbDisclosure {
    round0: [[u8; 20]; 8],
    round1: [[u8; 32]; 9],
    menus: [Vec<u8>; 3],
    cosig: Vec<u8>,
}
impl core::fmt::Debug for PqbDisclosure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PqbDisclosure(***)")
    }
}
impl PqbDisclosure {
    /// The eight selected 20-byte round-0 preimages, in request order.
    pub fn round0(&self) -> &[[u8; 20]; 8] {
        &self.round0
    }
    /// The nine selected SHA256-derived round-1 preimages, in request order.
    pub fn round1(&self) -> &[[u8; 32]; 9] {
        &self.round1
    }
    /// Only the three selected menu DER signatures, each with hashtype 0x01.
    pub fn menus(&self) -> &[Vec<u8>; 3] {
        &self.menus
    }
    /// Ordinary RFC6979 low-S DER co-signature with SIGHASH_ALL (no low-R grind).
    pub fn cosignature(&self) -> &[u8] {
        &self.cosig
    }
}

impl PqbVault {
    /// Prepare a disclosure for a canonical unsigned legacy transaction, an
    /// input and this vault's expected lock hash. Every scriptSig must be empty.
    ///
    /// Refuses malformed/context-free-invalid transactions, oversized requests,
    /// invalid input indices and a lock hash that does not belong to this vault.
    /// Funding, destination/fee approval and grind verification belong to the
    /// caller. After they pass, journal the returned digest before authorization.
    pub fn prepare_disclosure(
        &self,
        transaction: &[u8],
        input_index: usize,
        expected_lock_hash: &[u8; 32],
        selection: PqbSelection,
    ) -> Result<PqbRequest> {
        let tx = validate_transaction(transaction, input_index)?;
        let public = self.cached_public_material()?;
        if &public.script_sha256 != expected_lock_hash {
            return Err(invalid("locking script does not belong to vault"));
        }
        let cosig_hash = legacy_sighash(&tx, input_index, &public.script);
        let mut stage_hashes = [cosig_hash; 3];
        let dummy = super::menu::dummy_signatures();
        for (r, indices) in [selection.round0.as_slice(), selection.round1.as_slice()]
            .iter()
            .enumerate()
        {
            let mut code = public.script.clone();
            for index in *indices {
                code = find_and_delete(&code, &lock::push_data(&dummy[usize::from(*index)]));
            }
            stage_hashes[r + 1] = legacy_sighash(&tx, input_index, &code);
        }
        let mut h = Sha256::new_with_prefix(b"krusty/pqb/disclosure/v1\0");
        h.update(public.script_sha256);
        h.update((input_index as u64).to_be_bytes());
        h.update(selection.round0);
        h.update(selection.round1);
        h.update(selection.menus);
        h.update(transaction);
        Ok(PqbRequest {
            script_hash: public.script_sha256,
            selection,
            digest: h.finalize().into(),
            cosig_hash,
            stage_hashes,
        })
    }

    /// Release only this request's witnesses and co-sign its exact transaction.
    ///
    /// **Before calling**, the caller must persist `request.digest()` as exposed,
    /// and permanently refuse a different digest for this vault. The KMS does
    /// not store that journal or check puzzle solutions. A request prepared by
    /// another vault is refused before any secret is released.
    pub fn authorize(&self, request: &PqbRequest) -> Result<PqbDisclosure> {
        if self.cached_public_material()?.script_sha256 != request.script_hash {
            return Err(invalid("request belongs to another vault"));
        }
        let mut out = PqbDisclosure {
            round0: [[0; 20]; 8],
            round1: [[0; 32]; 9],
            menus: std::array::from_fn(|_| Vec::new()),
            cosig: Vec::new(),
        };
        for (slot, index) in out.round0.iter_mut().zip(request.selection.round0) {
            slot.copy_from_slice(self.hors(usize::from(index)).as_ref());
        }
        for (slot, index) in out.round1.iter_mut().zip(request.selection.round1) {
            let preimage = super::key::take_secret_digest(&mut Sha256::digest(
                self.hors(usize::from(index)).as_ref(),
            ));
            slot.copy_from_slice(preimage.as_ref());
        }
        let menus = self.menus()?;
        for (stage, menu) in menus.iter().enumerate() {
            out.menus[stage] = menu.signatures[usize::from(request.selection.menus[stage])].clone();
        }
        let signature: k256::ecdsa::Signature = self
            .cosig_key()?
            .sign_prehash(&request.cosig_hash)
            .map_err(|e| invalid(e.to_string()))?;
        out.cosig = signature.normalize_s().to_der().as_bytes().to_vec();
        out.cosig.push(1);
        Ok(out)
    }
}

fn validate_transaction(bytes: &[u8], input_index: usize) -> Result<Transaction> {
    if bytes.len() > 50_000 {
        return Err(invalid("unsigned transaction exceeds 50,000 bytes"));
    }
    let tx = Transaction::parse_legacy(bytes)?;
    if tx.inputs.is_empty() || tx.outputs.is_empty() || input_index >= tx.inputs.len() {
        return Err(invalid("empty transaction or invalid input index"));
    }
    let mut used = BTreeSet::new();
    for input in &tx.inputs {
        let prev = &input.previous_output;
        if !input.script_sig.is_empty()
            || (prev.txid == [0; 32] && prev.vout == u32::MAX)
            || !used.insert((prev.txid, prev.vout))
        {
            return Err(invalid("nonempty scriptSig or duplicate/null outpoint"));
        }
    }
    let mut total = 0u64;
    for output in &tx.outputs {
        total = total
            .checked_add(output.value)
            .ok_or_else(|| invalid("output amount overflow"))?;
        if total > 2_100_000_000_000_000 || output.script_pubkey.len() > 10_000 {
            return Err(invalid("output amount or script exceeds consensus limits"));
        }
    }
    // Leave a conservative 10,000-byte legacy scriptSig budget per input.
    if bytes.len() + tx.inputs.len() * 10_002 > 1_000_000 {
        return Err(invalid("transaction leaves no unlocking budget"));
    }
    Ok(tx)
}

fn legacy_sighash(tx: &Transaction, index: usize, code: &[u8]) -> [u8; 32] {
    let mut signing = tx.clone();
    for (i, input) in signing.inputs.iter_mut().enumerate() {
        input.script_sig = if i == index {
            code.to_vec()
        } else {
            Vec::new()
        };
    }
    let mut preimage = signing.serialize_legacy();
    preimage.extend(1u32.to_le_bytes());
    double_sha256(&preimage)
}

/// Core's FindAndDelete matches only opcode boundaries. The generated lock has
/// only direct pushes <=75, so payloads are skipped without interpreting them.
fn find_and_delete(script: &[u8], pattern: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < script.len() {
        if script[at..].starts_with(pattern) {
            at += pattern.len();
            continue;
        }
        let opcode = script[at];
        let end = at + 1 + if opcode <= 75 { usize::from(opcode) } else { 0 };
        out.extend_from_slice(&script[at..end]);
        at = end;
    }
    out
}
