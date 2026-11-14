//! Signature policies sharing the same strict PSBT validation.

use super::{
    checked_indices, decode_bounded, out_of_range, put_partial_signature, signable_amount,
    P2wpkhSigner, Psbt, BASE64,
};
use base64::Engine as _;
use krusty_kms_common::{KmsError, Result};

/// `sign_bitcoin_psbt_inputs` for a signer that is already set up.
pub(super) fn sign_with(
    signer: &P2wpkhSigner,
    psbt_base64: &str,
    input_indices: &[u32],
) -> Result<String> {
    sign_with_signature(signer, psbt_base64, input_indices, |hash| {
        signer.sign_sighash_all(hash)
    })
}

/// PQB's plain RFC6979 signatures, with the same strict PSBT ownership checks.
pub(crate) fn sign_pqb_deposit_psbt(
    private_key: &[u8; 32],
    psbt: &str,
    inputs: &[u32],
) -> Result<String> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    let key = SigningKey::from_slice(private_key)
        .map_err(|e| KmsError::InvalidPrivateKey(e.to_string()))?;
    sign_with_signature(&P2wpkhSigner::new(private_key)?, psbt, inputs, |hash| {
        let signature: Signature = key
            .sign_prehash(hash)
            .map_err(|e| KmsError::CryptoError(e.to_string()))?;
        let mut bytes = signature.normalize_s().to_der().as_bytes().to_vec();
        bytes.push(1);
        Ok(bytes)
    })
}

fn sign_with_signature(
    signer: &P2wpkhSigner,
    psbt_base64: &str,
    input_indices: &[u32],
    sign: impl Fn(&[u8; 32]) -> Result<Vec<u8>>,
) -> Result<String> {
    let mut psbt = Psbt::parse(&decode_bounded(psbt_base64)?)?;

    let indices = checked_indices(input_indices, psbt.inputs.len())?;
    let midstate = psbt.unsigned_tx.sighash_midstate();
    for index in indices {
        let amount = signable_amount(&psbt, index, signer)?;
        let sighash =
            psbt.unsigned_tx
                .p2wpkh_sighash_all(&midstate, index, &signer.pubkey_hash, amount)?;
        let signature = sign(&sighash)?;
        let map = psbt
            .inputs
            .get_mut(index)
            .ok_or_else(|| out_of_range(index))?;
        put_partial_signature(map, &signer.public_key, signature);
    }
    Ok(BASE64.encode(psbt.serialize()))
}
