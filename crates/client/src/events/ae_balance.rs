//! Decode the exact Cairo integer shape of Tongo AE hints from event felts.

use super::{AEBalance, KmsError, Result, StarknetRsFelt};

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

fn read_u64_limb(felt: &StarknetRsFelt) -> Result<[u8; 8]> {
    let bytes = felt.to_bytes_be();
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return Err(KmsError::DeserializationError(
            "AEBalance nonce exceeds 192 bits".to_string(),
        ));
    }
    let mut limb = [0u8; 8];
    limb.copy_from_slice(&bytes[24..]);
    Ok(limb)
}

/// Parse six felts: four `u512` ciphertext limbs and two `u256` nonce limbs.
pub(super) fn parse_ae_balance(felts: &[StarknetRsFelt], offset: usize) -> Result<AEBalance> {
    if felts.len() < offset + 6 {
        return Err(KmsError::DeserializationError(
            "Not enough felts for AEBalance".to_string(),
        ));
    }

    let mut ciphertext = [0u8; 64];
    for i in 0..4 {
        let limb = read_u128_limb(&felts[offset + i])?;
        // Cairo u512 encodes the least-significant 128-bit limb first.
        ciphertext[(3 - i) * 16..(4 - i) * 16].copy_from_slice(&limb);
    }

    let mut nonce = [0u8; 24];
    nonce[..8].copy_from_slice(&read_u64_limb(&felts[offset + 5])?);
    nonce[8..].copy_from_slice(&read_u128_limb(&felts[offset + 4])?);
    Ok(AEBalance { ciphertext, nonce })
}
