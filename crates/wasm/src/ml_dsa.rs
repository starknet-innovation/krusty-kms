//! WASM bindings for ML-DSA-65 (FIPS 204) post-quantum accounts.
//!
//! Four entry points, which together are everything a wallet needs to run an
//! ML-DSA account whose key lives in a phone's secure enclave:
//!
//! - the key commitment, which is the account contract's whole constructor
//!   argument and therefore half of its address preimage;
//! - signature verification, so a bad device response never reaches the network;
//! - the 1,830-felt transaction payload;
//! - a dummy payload for fee estimation, so previewing a fee needs no biometric
//!   prompt.
//!
//! There is deliberately no key generation and no signing here. The key never
//! leaves the device, so this boundary only ever handles public material: a
//! public key, a public signature, and a transaction hash.
//!
//! The 925-felt packed key is not exported. It is an intermediate of the
//! commitment and the payload, and no caller needs it on its own.

use krusty_kms_crypto::{
    ml_dsa_estimation_signature, ml_dsa_key_commitment, ml_dsa_signature_payload, ml_dsa_verify,
    ML_DSA_PUBLIC_KEY_BYTES, ML_DSA_SIGNATURE_BYTES,
};
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

fn hex_bytes(value: &str, label: &str, expected: usize) -> Result<Vec<u8>, JsValue> {
    let stripped = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let bytes = hex::decode(stripped)
        .map_err(|e| JsValue::from_str(&format!("Invalid {label} hex: {e}")))?;
    if bytes.len() != expected {
        return Err(JsValue::from_str(&format!(
            "{label} must be exactly {expected} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn felts_to_hex(felts: &[Felt]) -> Vec<String> {
    felts.iter().map(|felt| format!("{felt:#x}")).collect()
}

/// Compute the Poseidon commitment to an ML-DSA-65 public key.
///
/// This is `key_hash`: the account contract's entire constructor argument, and
/// what it recomputes on chain from the key each transaction carries. Deriving
/// it requires expanding the key (a SHAKE expansion plus an inverse NTT), which
/// is why it cannot be read off the key bytes.
///
/// # Arguments
/// * `public_key` - The 1,952-byte ML-DSA-65 public key as hex (with or without
///   `0x` prefix)
///
/// # Returns
/// The commitment as a hex string
#[wasm_bindgen(js_name = "mlDsaKeyCommitment")]
pub fn ml_dsa_key_commitment_wasm(public_key: &str) -> Result<String, JsValue> {
    let key = hex_bytes(public_key, "public key", ML_DSA_PUBLIC_KEY_BYTES)?;
    let commitment = ml_dsa_key_commitment(&key)
        .map_err(|e| JsValue::from_str(&format!("ML-DSA key commitment failed: {e}")))?;
    Ok(format!("{commitment:#x}"))
}

/// Verify an ML-DSA-65 signature over a transaction hash.
///
/// Returns `false` rather than throwing on malformed input, so a caller gating a
/// broadcast gets one decision it can trust instead of two outcomes to handle.
///
/// The message is the transaction hash as 32 big-endian bytes with an empty
/// FIPS 204 context. A signature made over a different encoding, or under a
/// context, is not a signature over this transaction and is rejected.
///
/// # Arguments
/// * `public_key` - The 1,952-byte public key as hex
/// * `transaction_hash` - The transaction hash as a hex felt
/// * `signature` - The 3,309-byte FIPS 204 signature as hex
///
/// # Returns
/// `true` only if the signature verifies under this key over this hash
#[wasm_bindgen(js_name = "mlDsaVerify")]
pub fn ml_dsa_verify_wasm(public_key: &str, transaction_hash: &str, signature: &str) -> bool {
    let Ok(key) = hex_bytes(public_key, "public key", ML_DSA_PUBLIC_KEY_BYTES) else {
        return false;
    };
    let Ok(bytes) = hex_bytes(signature, "signature", ML_DSA_SIGNATURE_BYTES) else {
        return false;
    };
    let Ok(hash) = Felt::from_hex(transaction_hash) else {
        return false;
    };
    ml_dsa_verify(&key, &hash, &bytes)
}

/// Build the 1,830-felt account signature for one transaction.
///
/// The packed verification key, the felt-native signature, and the witnesses the
/// on-chain Schwartz-Zippel check runs against. Throws rather than returning a
/// payload whose integer identity could not be proven, because the contract
/// rejects a wrong payload with no diagnosis.
///
/// # Arguments
/// * `public_key` - The 1,952-byte public key as hex
/// * `transaction_hash` - The transaction hash as a hex felt
/// * `signature` - The 3,309-byte FIPS 204 signature as hex
///
/// # Returns
/// 1,830 felts as hex strings, in the order the contract reads them
#[wasm_bindgen(js_name = "mlDsaSignaturePayload")]
pub fn ml_dsa_signature_payload_wasm(
    public_key: &str,
    transaction_hash: &str,
    signature: &str,
) -> Result<Vec<String>, JsValue> {
    let key = hex_bytes(public_key, "public key", ML_DSA_PUBLIC_KEY_BYTES)?;
    let bytes = hex_bytes(signature, "signature", ML_DSA_SIGNATURE_BYTES)?;
    let hash = Felt::from_hex(transaction_hash)
        .map_err(|e| JsValue::from_str(&format!("Invalid transaction hash: {e}")))?;
    let payload = ml_dsa_signature_payload(&key, &hash, &bytes)
        .map_err(|e| JsValue::from_str(&format!("ML-DSA payload failed: {e}")))?;
    Ok(felts_to_hex(&payload))
}

/// Build a well-formed ML-DSA signature that verifies against nothing, for fee
/// estimation.
///
/// Estimating a fee normally runs the account's validation, which for this
/// family would mean a biometric prompt just to preview a fee. Instead the
/// estimate is taken as a query-version transaction carrying this payload: the
/// contract runs its full verifier — so the estimate includes the real
/// validation cost — then tolerates the failing verdict, which is safe because
/// the sequencer never executes a query-version transaction.
///
/// It is a pure function of the public key: no signing, no randomness, no state.
///
/// # Arguments
/// * `public_key` - The 1,952-byte public key as hex
///
/// # Returns
/// 1,830 felts as hex strings
#[wasm_bindgen(js_name = "mlDsaEstimationSignature")]
pub fn ml_dsa_estimation_signature_wasm(public_key: &str) -> Result<Vec<String>, JsValue> {
    let key = hex_bytes(public_key, "public key", ML_DSA_PUBLIC_KEY_BYTES)?;
    let payload = ml_dsa_estimation_signature(&key)
        .map_err(|e| JsValue::from_str(&format!("ML-DSA estimation signature failed: {e}")))?;
    Ok(felts_to_hex(&payload))
}

#[cfg(test)]
mod tests;
