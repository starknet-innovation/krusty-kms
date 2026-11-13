//! Decode the exact Cairo integer shape of Tongo AE hints from event felts.

use super::{AEBalance, KmsError, Result, StarknetRsFelt};
use crate::types::AEBalanceLayout;

fn read_u128_limb(felt: &StarknetRsFelt) -> Result<[u8; 16]> {
    let bytes = felt.to_bytes_be();
    if bytes[..16].iter().any(|byte| *byte != 0) {
        return Err(KmsError::DeserializationError(
            "AEBalance u128 limb exceeds its width".to_string(),
        ));
    }
    let mut limb = [0u8; 16];
    limb.copy_from_slice(&bytes[16..]);
    Ok(limb)
}

/// Parse six felts: four `u512` ciphertext limbs and two `u256` nonce limbs.
pub(super) fn parse_ae_balance(felts: &[StarknetRsFelt], offset: usize) -> Result<AEBalance> {
    if felts.len() < offset + 6 {
        return Err(KmsError::DeserializationError(
            "Not enough felts for AEBalance".to_string(),
        ));
    }

    let mut limbs = [[0u8; 16]; 6];
    for (limb, felt) in limbs.iter_mut().zip(&felts[offset..offset + 6]) {
        *limb = read_u128_limb(felt)?;
    }

    // Older Krusty calldata put the nonce in the most-significant 24 bytes
    // and wrote ciphertext limbs in byte order. Its low nonce limb ends in
    // eight zero bytes; current Cairo encoding puts the nonce in the least-
    // significant 24 bytes and reverses the ciphertext limbs. A current
    // random nonce can collide with the old shape with probability 2^-64.
    let legacy =
        limbs[4][8..].iter().all(|byte| *byte == 0) || limbs[5][..8].iter().any(|byte| *byte != 0);
    Ok(if legacy {
        let (ciphertext, nonce) = parse_legacy_ae_balance(&limbs);
        let mut tail = [0u8; 8];
        tail.copy_from_slice(&limbs[4][8..]);
        AEBalance::from_decoded(ciphertext, nonce, AEBalanceLayout::Legacy, tail)
    } else {
        let (ciphertext, nonce) = parse_current_ae_balance(&limbs);
        AEBalance::from_decoded(ciphertext, nonce, AEBalanceLayout::Current, [0u8; 8])
    })
}

fn parse_legacy_ae_balance(limbs: &[[u8; 16]; 6]) -> ([u8; 64], [u8; 24]) {
    let mut ciphertext = [0u8; 64];
    for (chunk, limb) in ciphertext
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(&limbs[..4])
    {
        chunk.copy_from_slice(limb);
    }
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(&limbs[5]);
    nonce[16..].copy_from_slice(&limbs[4][..8]);
    (ciphertext, nonce)
}

fn parse_current_ae_balance(limbs: &[[u8; 16]; 6]) -> ([u8; 64], [u8; 24]) {
    let mut ciphertext = [0u8; 64];
    for (chunk, limb) in ciphertext
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(limbs[..4].iter().rev())
    {
        chunk.copy_from_slice(limb);
    }
    let mut nonce = [0u8; 24];
    nonce[..8].copy_from_slice(&limbs[5][8..]);
    nonce[8..].copy_from_slice(&limbs[4]);
    (ciphertext, nonce)
}
