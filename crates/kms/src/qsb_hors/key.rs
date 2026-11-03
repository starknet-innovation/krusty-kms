//! `K` and everything derived from it. Nothing here is reachable from outside
//! `qsb_hors`: the parent exposes only commitments and validated reveals.

use super::{
    QsbCommitment, QsbCommitments, QsbPreimages, QsbRevealIndices, QsbVault, QSB_REVEALS,
    QSB_SECRETS_PER_ROUND, QSB_SECRET_LEN,
};
use crate::mnemonic::mnemonic_to_seed;
use hmac::{Hmac, KeyInit, Mac};
use krusty_kms_common::{KmsError, Result};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

const PROFILE: &[u8; 11] = b"QSB-HORS-v1";
const SLIP21_LABEL: &[u8] = b"QSB-HORS";
const ROOT_TAG: &[u8] = b"QSB-HORS-v1/root";

/// `K`, the SLIP-0021 child `"QSB-HORS"` of the BIP-39 seed. Wiped on drop.
pub(super) struct QsbKey(pub(super) Zeroizing<[u8; 32]>);

impl QsbKey {
    pub(super) fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>) -> Result<Self> {
        let seed = Zeroizing::new(mnemonic_to_seed(mnemonic, passphrase.unwrap_or(""))?);
        Self::from_seed(seed.as_ref())
    }

    pub(super) fn from_seed(seed: &[u8]) -> Result<Self> {
        slip21_child_key(seed, SLIP21_LABEL).map(Self)
    }

    /// `s[v][round][index]`.
    pub(super) fn secret(
        &self,
        vault: QsbVault,
        round: u8,
        index: u16,
    ) -> Result<Zeroizing<[u8; QSB_SECRET_LEN]>> {
        // Byte 11 stays 0x00, the separator after the profile name.
        let mut message = [0u8; 20];
        message[..11].copy_from_slice(PROFILE);
        message[12] = vault.net();
        message[13..17].copy_from_slice(&vault.index().to_be_bytes());
        message[17] = round;
        message[18..].copy_from_slice(&index.to_be_bytes());
        let mut mac = hmac_sha256(self.0.as_ref(), &message)?;
        Ok(take_output(&mut mac[..]))
    }

    pub(super) fn commitments(&self, vault: QsbVault) -> Result<QsbCommitments> {
        let round0 = self.round_commitments(vault, 0)?;
        let round1 = self.round_commitments(vault, 1)?;
        let mut root = Sha256::new_with_prefix(ROOT_TAG);
        for commitment in round0.iter().chain(&round1) {
            root.update(commitment);
        }
        Ok(QsbCommitments {
            round0,
            round1,
            root: root.finalize().into(),
        })
    }

    fn round_commitments(
        &self,
        vault: QsbVault,
        round: u8,
    ) -> Result<[QsbCommitment; QSB_SECRETS_PER_ROUND]> {
        let mut commitments = [[0u8; QSB_SECRET_LEN]; QSB_SECRETS_PER_ROUND];
        for (index, commitment) in (0u16..).zip(commitments.iter_mut()) {
            *commitment = hash160(self.secret(vault, round, index)?.as_ref());
        }
        Ok(commitments)
    }

    /// The secrets `indices` names, in disclosure order.
    pub(super) fn preimages(
        &self,
        vault: QsbVault,
        indices: &QsbRevealIndices,
    ) -> Result<QsbPreimages> {
        let mut preimages = QsbPreimages([[0u8; QSB_SECRET_LEN]; QSB_REVEALS]);
        for (slot, (round, index)) in preimages.0.iter_mut().zip(indices.secrets()) {
            slot.copy_from_slice(self.secret(vault, round, index)?.as_ref());
        }
        Ok(preimages)
    }
}

/// The key of the SLIP-0021 node at the single label `label`.
pub(super) fn slip21_child_key(seed: &[u8], label: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let master = hmac_sha512(b"Symmetric key seed", &[seed])?;
    let mut node = hmac_sha512(&master[..32], &[&[0x00], label])?;
    Ok(take_output(&mut node[32..]))
}

fn hmac_sha512(key: &[u8], message: &[&[u8]]) -> Result<Zeroizing<[u8; 64]>> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(key_length_error)?;
    for part in message {
        mac.update(part);
    }
    Ok(take_output(&mut mac.finalize().into_bytes()))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(key_length_error)?;
    mac.update(message);
    Ok(take_output(&mut mac.finalize().into_bytes()))
}

fn key_length_error(error: impl core::fmt::Display) -> KmsError {
    KmsError::CryptoError(error.to_string())
}

/// Copy a secret-bearing buffer into a wiped-on-drop array, then wipe it.
fn take_output<const N: usize>(output: &mut [u8]) -> Zeroizing<[u8; N]> {
    let mut taken = Zeroizing::new([0u8; N]);
    taken.copy_from_slice(&output[..N]);
    output.zeroize();
    taken
}

pub(super) fn hash160(data: &[u8]) -> QsbCommitment {
    Ripemd160::digest(Sha256::digest(data)).into()
}
