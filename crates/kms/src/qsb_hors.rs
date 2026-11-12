//! QSB-HORS-v1 vault secrets for Quantum Safe Bitcoin.
//!
//! Implements the derivation profile of the draft BIP "QSB Wallet Secret
//! Management". A vault `(net, v)` holds 2 × 150 one-time 20-byte secrets:
//!
//! ```text
//! S          = BIP-39 seed of (mnemonic, passphrase)              (64 bytes)
//! K          = SLIP-0021 child "QSB-HORS" of S                    (32 bytes)
//! s[v][r][i] = HMAC-SHA256(K, "QSB-HORS-v1" || 0x00 || u8(net) || u32be(v)
//!                             || u8(r) || u16be(i))[0..20]
//! c[v][r][i] = HASH160(s[v][r][i])
//! R[v]       = SHA256("QSB-HORS-v1/root" || c[v][0][0..150] || c[v][1][0..150])
//! ```
//!
//! # Trust boundary
//!
//! These functions are stateless primitives. They never return the seed, `K`,
//! a complete secret set, or any secret outside a validated disclosure request.
//! The BIP's disclosure journal belongs to the caller, which must durably
//! record a request as `exposed`, with the digest from [`qsb_reveal_digest`],
//! before calling [`reveal_qsb_preimages`]. Nothing here verifies that a
//! transaction actually spends a vault or that the indices solve its puzzle.
//!
//! All parameters are validated before any derivation: [`QsbVault`] and
//! [`QsbRevealIndices`] can only hold values the profile accepts.
//!
//! # Memory
//!
//! `K`, every value keyed by it, and every secret live only in buffers that
//! are wiped when they drop: `Zeroizing` arrays, [`QsbPreimages`], and `sha2`
//! hashers built with their `zeroize` feature. HMAC is computed locally so
//! that its padded key is one of those buffers. Not covered: copies the
//! compiler makes when it moves a value, register spills, the SHA-2
//! compression functions' stack temporaries, and what the BIP-39 seed
//! step leaves outside the stack (see `mnemonic`'s Memory section). Commitments, `SHA256(secret)`, roots, and digests are
//! public and not wiped.

mod key;
mod transaction;

#[cfg(test)]
mod tests;

use key::QsbKey;
use krusty_kms_common::{KmsError, Result};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of a HORS secret and of its HASH160 commitment.
pub const QSB_SECRET_LEN: usize = 20;
/// Secrets per round.
pub const QSB_SECRETS_PER_ROUND: usize = 150;
/// Indices a withdrawal discloses from round 0.
pub const QSB_ROUND0_REVEALS: usize = 8;
/// Indices a withdrawal discloses from round 1.
pub const QSB_ROUND1_REVEALS: usize = 7;
/// Preimages a withdrawal discloses in total.
pub const QSB_REVEALS: usize = QSB_ROUND0_REVEALS + QSB_ROUND1_REVEALS;
/// Largest `T` in bytes, checked before parsing (and, in WASM, before the hex
/// is copied in).
///
/// `T` omits every scriptSig and witness, which the real spend adds: the 15
/// preimages and the rest of the QSB unlocking data. `T` is fixed once secrets
/// are exposed, so a `T` whose signed spend exceeds Bitcoin Core's standard
/// weight (400,000 WU) would strand the vault. This cap alone never ensured
/// that, because each input costs only 41 bytes in `T` but may add up to about
/// 40,000 WU when signed. Once parsed, `T` must therefore also satisfy
/// `4 × len(T) + 2 + inputs × 40,117 ≤ 400,000`, budgeting a full 10,000-byte
/// legacy scriptSig and a P2WPKH witness per input. That allows at most 9
/// inputs, and at most 4 at this cap; a real withdrawal's `T` is a few hundred
/// bytes with two inputs.
pub const QSB_MAX_TRANSACTION_SIZE: usize = 50_000;

const REVEAL_TAG: &[u8] = b"QSB-HORS-v1/reveal";
const NET_TEST: u8 = 0x01;
const MAX_VAULT_INDEX: u32 = 0x7fff_ffff;

/// One HASH160 commitment, `c[v][r][i]`.
pub type QsbCommitment = [u8; QSB_SECRET_LEN];

fn invalid_parameter(message: String) -> KmsError {
    KmsError::InvalidDerivationPath(message)
}

/// A validated `(net, v)` pair naming one vault key set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QsbVault {
    net: u8,
    index: u32,
}

impl QsbVault {
    /// Validate a derivation namespace and vault index.
    ///
    /// `net` must be `0x00` (Bitcoin mainnet) or `0x01` (the shared test
    /// namespace for testnet, signet, and regtest); `index` must be below
    /// `2^31`.
    ///
    /// # Errors
    ///
    /// Returns [`KmsError::InvalidDerivationPath`] for any other value.
    pub fn new(net: u8, index: u32) -> Result<Self> {
        if net > NET_TEST {
            return Err(invalid_parameter(format!(
                "QSB namespace 0x{net:02x} must be 0x00 (mainnet) or 0x01 (test)"
            )));
        }
        if index > MAX_VAULT_INDEX {
            return Err(invalid_parameter(format!(
                "QSB vault index {index} must be below 2^31"
            )));
        }
        Ok(Self { net, index })
    }

    /// The derivation namespace byte.
    pub fn net(&self) -> u8 {
        self.net
    }

    /// The vault index `v`.
    pub fn index(&self) -> u32 {
        self.index
    }
}

/// A validated disclosure request: which secrets of a vault to reveal.
///
/// Holds exactly 8 distinct round-0 indices and 7 distinct round-1 indices,
/// all below 150, in the caller's order. The order is significant and is
/// never sorted. The same index may appear in both rounds, since it names a
/// different secret in each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QsbRevealIndices {
    round0: [u16; QSB_ROUND0_REVEALS],
    round1: [u16; QSB_ROUND1_REVEALS],
}

impl QsbRevealIndices {
    /// Validate the round-0 and round-1 index sequences.
    ///
    /// # Errors
    ///
    /// Returns [`KmsError::InvalidDerivationPath`] if a round has the wrong
    /// number of indices, repeats an index, or names an index above 149.
    pub fn new(round0: &[u16], round1: &[u16]) -> Result<Self> {
        Ok(Self {
            round0: reveal_round(0, round0)?,
            round1: reveal_round(1, round1)?,
        })
    }

    /// The round-0 indices, in request order.
    pub fn round0(&self) -> &[u16; QSB_ROUND0_REVEALS] {
        &self.round0
    }

    /// The round-1 indices, in request order.
    pub fn round1(&self) -> &[u16; QSB_ROUND1_REVEALS] {
        &self.round1
    }

    /// `(round, index)` pairs in disclosure order: round 0's, then round 1's.
    fn secrets(&self) -> impl Iterator<Item = (u8, u16)> + '_ {
        let round0 = self.round0.iter().map(|&index| (0, index));
        round0.chain(self.round1.iter().map(|&index| (1, index)))
    }
}

fn reveal_round<const N: usize>(round: u8, indices: &[u16]) -> Result<[u16; N]> {
    let indices: [u16; N] = indices.try_into().map_err(|_| {
        invalid_parameter(format!(
            "QSB round {round} needs exactly {N} indices, got {}",
            indices.len()
        ))
    })?;
    for (position, &index) in indices.iter().enumerate() {
        if usize::from(index) >= QSB_SECRETS_PER_ROUND {
            return Err(invalid_parameter(format!(
                "QSB round {round} index {index} is outside [0, 149]"
            )));
        }
        if indices[..position].contains(&index) {
            return Err(invalid_parameter(format!(
                "QSB round {round} repeats index {index}"
            )));
        }
    }
    Ok(indices)
}

/// The public commitments of one vault and their root `R`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QsbCommitments {
    /// `c[v][0][0..150]`, in index order.
    pub round0: [QsbCommitment; QSB_SECRETS_PER_ROUND],
    /// `c[v][1][0..150]`, in index order.
    pub round1: [QsbCommitment; QSB_SECRETS_PER_ROUND],
    /// `R[v]`, the flat SHA-256 over both rounds. Not a Merkle root.
    pub root: [u8; 32],
}

/// The transaction binding of a disclosure request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QsbRevealDigest {
    /// `B = SHA256(T)`.
    pub binding: [u8; 32],
    /// `D = SHA256("QSB-HORS-v1/reveal" || I || B)`.
    pub digest: [u8; 32],
}

/// The preimages of one disclosure: round 0's, then round 1's, each in
/// request order. Wiped on drop; `Debug` redacts them.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct QsbPreimages([[u8; QSB_SECRET_LEN]; QSB_REVEALS]);

impl QsbPreimages {
    /// All 15 preimages in disclosure order.
    pub fn as_array(&self) -> &[[u8; QSB_SECRET_LEN]; QSB_REVEALS] {
        &self.0
    }
}

impl core::fmt::Debug for QsbPreimages {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("QsbPreimages(***)")
    }
}

/// Derive the 300 commitments and the root of one vault.
///
/// `mnemonic` must be a valid BIP-39 phrase; `passphrase` is its optional
/// BIP-39 passphrase (both NFKD-normalized). Neither `K` nor any secret is
/// returned. Deriving commitments does not allocate the vault: the caller's
/// journal decides whether it is safe to fund.
///
/// # Errors
///
/// Returns [`KmsError::InvalidMnemonic`] for an invalid phrase.
pub fn derive_qsb_commitments(
    mnemonic: &str,
    vault: QsbVault,
    passphrase: Option<&str>,
) -> Result<QsbCommitments> {
    QsbKey::from_mnemonic(mnemonic, passphrase)?.commitments(vault)
}

/// Bind a disclosure request to the transaction that will spend the vault.
///
/// `transaction` is the BIP's `T`: the complete legacy serialization of the
/// spending transaction with every scriptSig empty and no witness data.
/// `T` is parsed and refused unless it is exactly that: no segwit marker, no
/// non-empty scriptSig, no truncation, no trailing bytes, and no field that
/// makes the transaction invalid under Bitcoin's context-free rules. A
/// caller-supplied binding hash is never accepted.
///
/// # Errors
///
/// Returns [`KmsError::DeserializationError`] when `transaction` is not a
/// valid `T`.
pub fn qsb_reveal_digest(
    transaction: &[u8],
    indices: &QsbRevealIndices,
) -> Result<QsbRevealDigest> {
    transaction::validate(transaction)?;
    let binding: [u8; 32] = Sha256::digest(transaction).into();
    Ok(QsbRevealDigest {
        binding,
        digest: reveal_digest(indices, &binding),
    })
}

/// Reveal exactly the secrets a validated disclosure request names.
///
/// Returns 15 preimages: round 0's then round 1's, in request order. The
/// caller must already have durably recorded this request as `exposed`.
///
/// # Errors
///
/// Returns [`KmsError::InvalidMnemonic`] for an invalid phrase.
pub fn reveal_qsb_preimages(
    mnemonic: &str,
    vault: QsbVault,
    indices: &QsbRevealIndices,
    passphrase: Option<&str>,
) -> Result<QsbPreimages> {
    QsbKey::from_mnemonic(mnemonic, passphrase)?.preimages(vault, indices)
}

/// `D` for a binding `B` already derived from `T`. `I` is every index as
/// `u16be`, round 0's then round 1's.
fn reveal_digest(indices: &QsbRevealIndices, binding: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new_with_prefix(REVEAL_TAG);
    for (_, index) in indices.secrets() {
        digest.update(index.to_be_bytes());
    }
    digest.chain_update(binding).finalize().into()
}
