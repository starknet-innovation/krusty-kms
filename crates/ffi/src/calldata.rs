//! Calldata encoding FFI functions.
//!
//! Each function takes a JSON input containing proof data + contract addresses,
//! and outputs a JSON object describing the calls to submit on-chain:
//!
//! ```json
//! {"calls": [{"to": "0x...", "selector": "0x...", "calldata": ["0x...", ...]}]}
//! ```

#![allow(dead_code)] // Deserialized structs have fields read by serde

use std::ffi::c_char;
use std::panic::catch_unwind;

use krusty_kms_common::{AuditProof, ElGamalCiphertext, PoeProof, ProofOfTransfer};
use krusty_kms_sdk::serialization;
use serde::{Deserialize, Serialize};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

use crate::error::*;
use crate::helpers::write_string_output;

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CallJson {
    to: String,
    selector: String,
    calldata: Vec<String>,
}

#[derive(Serialize)]
struct CallsResult {
    calls: Vec<CallJson>,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn felt_hex(f: &Felt) -> String {
    format!("{:#x}", f)
}

fn parse_felt(s: &str) -> Result<Felt, i32> {
    Felt::from_hex(s).map_err(|_| KMS_ERR_INVALID_INPUT)
}

fn selector(name: &str) -> Felt {
    // Starknet selector = lower 250 bits of keccak256(name)
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(name.as_bytes());
    let result = hasher.finalize();
    // Take lower 250 bits
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    // Mask the top 6 bits to stay within Stark field
    bytes[0] &= 0x03;
    Felt::from_bytes_be_slice(&bytes)
}

fn felts_to_hex_vec(felts: &[Felt]) -> Vec<String> {
    felts.iter().map(felt_hex).collect()
}

fn serialize_ae_balance_felts(ct: &[u8; 64], nonce: &[u8; 24]) -> Result<Vec<Felt>, i32> {
    serialization::serialize_ae_balance(ct, nonce).map_err(|_| KMS_ERR_CRYPTO)
}

fn serialize_poe_felts(proof: &PoeProof) -> Result<Vec<Felt>, i32> {
    serialization::serialize_poe_proof(proof).map_err(|_| KMS_ERR_CRYPTO)
}

fn decode_hex_bytes<const N: usize>(hex_data: &str) -> Result<[u8; N], i32> {
    let bytes = hex::decode(hex_data).map_err(|_| KMS_ERR_INVALID_INPUT)?;
    if bytes.len() != N {
        return Err(KMS_ERR_INVALID_INPUT);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn append_hint_felts(
    calldata: &mut Vec<String>,
    hint_ciphertext_hex: &str,
    hint_nonce_hex: &str,
) -> Result<(), i32> {
    let ct = decode_hex_bytes::<64>(hint_ciphertext_hex)?;
    let nonce = decode_hex_bytes::<24>(hint_nonce_hex)?;
    let hint_felts = serialize_ae_balance_felts(&ct, &nonce)?;
    calldata.extend(felts_to_hex_vec(&hint_felts));
    Ok(())
}

fn parse_projective_point(x: &str, y: &str) -> Result<ProjectivePoint, i32> {
    let x = parse_felt(x)?;
    let y = parse_felt(y)?;
    ProjectivePoint::from_affine(x, y).map_err(|_| KMS_ERR_INVALID_INPUT)
}

#[derive(Deserialize)]
struct AuditJsonPoint {
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct AuditJsonCipherBalance {
    l: AuditJsonPoint,
    r: AuditJsonPoint,
}

#[derive(Deserialize)]
struct AuditJsonData {
    audited_balance: AuditJsonCipherBalance,
    hint_ciphertext: String,
    hint_nonce: String,
    proof: AuditProof,
}

fn append_audit_option(calldata: &mut Vec<String>, audit_json: Option<&str>) -> Result<(), i32> {
    match audit_json {
        Some(audit_json) => {
            let audit: AuditJsonData =
                serde_json::from_str(audit_json).map_err(|_| KMS_ERR_JSON)?;

            // CairoOption::Some
            calldata.push(felt_hex(&Felt::ZERO));

            let l = parse_projective_point(&audit.audited_balance.l.x, &audit.audited_balance.l.y)?;
            let r = parse_projective_point(&audit.audited_balance.r.x, &audit.audited_balance.r.y)?;
            let balance_felts =
                serialization::serialize_cipher_balance(&ElGamalCiphertext { l, r })
                    .map_err(|_| KMS_ERR_CRYPTO)?;
            calldata.extend(felts_to_hex_vec(&balance_felts));

            append_hint_felts(calldata, &audit.hint_ciphertext, &audit.hint_nonce)?;

            let audit_proof_felts =
                serialization::serialize_audit_proof(&audit.proof).map_err(|_| KMS_ERR_CRYPTO)?;
            calldata.extend(felts_to_hex_vec(&audit_proof_felts));
            Ok(())
        }
        None => {
            // CairoOption::None
            calldata.push(felt_hex(&Felt::ONE));
            Ok(())
        }
    }
}

fn build_calls_json(calls: Vec<CallJson>) -> Result<String, i32> {
    serde_json::to_string(&CallsResult { calls }).map_err(|_| KMS_ERR_JSON)
}

// ---------------------------------------------------------------------------
// ERC20 approve
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ApproveParams {
    erc20_address: String,
    spender: String,
    amount: String,
}

#[no_mangle]
pub unsafe extern "C" fn kms_encode_erc20_approve(
    params_json: *const c_char,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let json_str = match crate::helpers::read_cstr(params_json) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let params: ApproveParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let amount: u128 = match params.amount.parse() {
            Ok(a) => a,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };

        let spender = match parse_felt(&params.spender) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let (low, high) = serialization::u128_to_u256(amount);

        let call = CallJson {
            to: params.erc20_address,
            selector: felt_hex(&selector("approve")),
            calldata: vec![felt_hex(&spender), felt_hex(&low), felt_hex(&high)],
        };

        match build_calls_json(vec![call]) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Fund calls
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EncodeFundParams {
    tongo_address: String,
    erc20_address: String,
    rate: String,
    proof_result_json: String,
    hint_ciphertext_hex: String,
    hint_nonce_hex: String,
}

#[derive(Deserialize)]
struct FundProofData {
    y_x: String,
    y_y: String,
    proof_json: String,
    amount: String,
    audit_json: Option<String>,
}

#[no_mangle]
pub unsafe extern "C" fn kms_encode_fund_calls(
    params_json: *const c_char,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let json_str = match crate::helpers::read_cstr(params_json) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let params: EncodeFundParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let proof_data: FundProofData = match serde_json::from_str(&params.proof_result_json) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let amount: u128 = match proof_data.amount.parse() {
            Ok(a) => a,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        let rate: u128 = match params.rate.parse() {
            Ok(r) => r,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };

        let tongo_addr = match parse_felt(&params.tongo_address) {
            Ok(f) => f,
            Err(e) => return e,
        };

        // Build approve call
        let approve_amount = match amount.checked_mul(rate) {
            Some(v) => v,
            None => return KMS_ERR_INVALID_INPUT,
        };
        let (low, high) = serialization::u128_to_u256(approve_amount);
        let approve_call = CallJson {
            to: params.erc20_address.clone(),
            selector: felt_hex(&selector("approve")),
            calldata: vec![felt_hex(&tongo_addr), felt_hex(&low), felt_hex(&high)],
        };

        // Build fund calldata
        let mut calldata = Vec::new();
        let y_x = match parse_felt(&proof_data.y_x) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let y_y = match parse_felt(&proof_data.y_y) {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.push(felt_hex(&y_x));
        calldata.push(felt_hex(&y_y));
        calldata.push(felt_hex(&Felt::from(amount)));

        // Hint
        if let Err(e) = append_hint_felts(
            &mut calldata,
            &params.hint_ciphertext_hex,
            &params.hint_nonce_hex,
        ) {
            return e;
        }

        // Proof
        let poe: PoeProof = match serde_json::from_str(&proof_data.proof_json) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };
        let proof_felts = match serialize_poe_felts(&poe) {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.extend(felts_to_hex_vec(&proof_felts));

        // Audit
        if let Err(e) = append_audit_option(&mut calldata, proof_data.audit_json.as_deref()) {
            return e;
        }

        let fund_call = CallJson {
            to: params.tongo_address,
            selector: felt_hex(&selector("fund")),
            calldata,
        };

        match build_calls_json(vec![approve_call, fund_call]) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Rollover calls
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EncodeRolloverParams {
    tongo_address: String,
    proof_result_json: String,
    hint_ciphertext_hex: String,
    hint_nonce_hex: String,
}

#[derive(Deserialize)]
struct RolloverProofData {
    y_x: String,
    y_y: String,
    proof_json: String,
}

#[no_mangle]
pub unsafe extern "C" fn kms_encode_rollover_calls(
    params_json: *const c_char,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let json_str = match crate::helpers::read_cstr(params_json) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let params: EncodeRolloverParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let proof_data: RolloverProofData = match serde_json::from_str(&params.proof_result_json) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let mut calldata = Vec::new();

        let y_x = match parse_felt(&proof_data.y_x) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let y_y = match parse_felt(&proof_data.y_y) {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.push(felt_hex(&y_x));
        calldata.push(felt_hex(&y_y));

        // Hint
        if let Err(e) = append_hint_felts(
            &mut calldata,
            &params.hint_ciphertext_hex,
            &params.hint_nonce_hex,
        ) {
            return e;
        }

        let poe: PoeProof = match serde_json::from_str(&proof_data.proof_json) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };
        let proof_felts = match serialize_poe_felts(&poe) {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.extend(felts_to_hex_vec(&proof_felts));

        let call = CallJson {
            to: params.tongo_address,
            selector: felt_hex(&selector("rollover")),
            calldata,
        };

        match build_calls_json(vec![call]) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Transfer calls
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EncodeTransferParams {
    tongo_address: String,
    proof_result_json: String,
    hint_ciphertext_hex: String,
    hint_nonce_hex: String,
}

#[derive(Deserialize)]
struct TransferProofData {
    transfer_l_x: String,
    transfer_l_y: String,
    transfer_r_x: String,
    transfer_r_y: String,
    self_l_x: String,
    self_l_y: String,
    self_r_x: String,
    self_r_y: String,
    new_balance_l_x: String,
    new_balance_l_y: String,
    new_balance_r_x: String,
    new_balance_r_y: String,
    proof_json: String,
    audit_balance_json: Option<String>,
    audit_transfer_json: Option<String>,
}

#[no_mangle]
pub unsafe extern "C" fn kms_encode_transfer_calls(
    params_json: *const c_char,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let json_str = match crate::helpers::read_cstr(params_json) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let params: EncodeTransferParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };
        let proof_data: TransferProofData = match serde_json::from_str(&params.proof_result_json) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let mut calldata = Vec::new();

        // Transfer balance for recipient: L, R
        for (x, y) in [
            (&proof_data.transfer_l_x, &proof_data.transfer_l_y),
            (&proof_data.transfer_r_x, &proof_data.transfer_r_y),
            (&proof_data.self_l_x, &proof_data.self_l_y),
            (&proof_data.self_r_x, &proof_data.self_r_y),
        ] {
            let fx = match parse_felt(x) {
                Ok(f) => f,
                Err(e) => return e,
            };
            let fy = match parse_felt(y) {
                Ok(f) => f,
                Err(e) => return e,
            };
            calldata.push(felt_hex(&fx));
            calldata.push(felt_hex(&fy));
        }

        // Hint
        if let Err(e) = append_hint_felts(
            &mut calldata,
            &params.hint_ciphertext_hex,
            &params.hint_nonce_hex,
        ) {
            return e;
        }

        // Transfer proof (serialized as JSON, contains all commitments and range proofs)
        let transfer_proof: ProofOfTransfer = match serde_json::from_str(&proof_data.proof_json) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };
        let proof_felts = match serialization::serialize_proof_of_transfer(&transfer_proof)
            .map_err(|_| KMS_ERR_CRYPTO)
        {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.extend(felts_to_hex_vec(&proof_felts));

        // Audit for balance and transfer ciphers
        if let Err(e) = append_audit_option(&mut calldata, proof_data.audit_balance_json.as_deref())
        {
            return e;
        }
        if let Err(e) =
            append_audit_option(&mut calldata, proof_data.audit_transfer_json.as_deref())
        {
            return e;
        }

        let call = CallJson {
            to: params.tongo_address,
            selector: felt_hex(&selector("transfer")),
            calldata,
        };

        match build_calls_json(vec![call]) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Withdraw calls
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EncodeWithdrawParams {
    tongo_address: String,
    proof_result_json: String,
    hint_ciphertext_hex: String,
    hint_nonce_hex: String,
}

#[derive(Deserialize)]
struct WithdrawProofData {
    y_x: String,
    y_y: String,
    a_x_x: String,
    a_x_y: String,
    a_r_x: String,
    a_r_y: String,
    a_x2: String,
    a_y2: String,
    a_v_x: String,
    a_v_y: String,
    sx: String,
    sb: String,
    sr: String,
    r_aux_x: String,
    r_aux_y: String,
    range_json: String,
    amount: String,
    recipient: String,
    audit_json: Option<String>,
}

#[no_mangle]
pub unsafe extern "C" fn kms_encode_withdraw_calls(
    params_json: *const c_char,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let json_str = match crate::helpers::read_cstr(params_json) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let params: EncodeWithdrawParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };
        let pd: WithdrawProofData = match serde_json::from_str(&params.proof_result_json) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let amount: u128 = match pd.amount.parse() {
            Ok(a) => a,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };

        let mut calldata = vec![
            // from (public key)
            pd.y_x.clone(),
            pd.y_y.clone(),
            // to (recipient)
            pd.recipient.clone(),
            // amount
            felt_hex(&Felt::from(amount)),
        ];

        // Hint
        if let Err(e) = append_hint_felts(
            &mut calldata,
            &params.hint_ciphertext_hex,
            &params.hint_nonce_hex,
        ) {
            return e;
        }

        // Proof commitments
        for hex_val in [
            &pd.a_x_x, &pd.a_x_y, &pd.a_r_x, &pd.a_r_y, &pd.a_x2, &pd.a_y2, &pd.a_v_x, &pd.a_v_y,
        ] {
            calldata.push(hex_val.clone());
        }
        // Scalar responses
        calldata.push(pd.sx.clone());
        calldata.push(pd.sb.clone());
        calldata.push(pd.sr.clone());
        // R_aux
        calldata.push(pd.r_aux_x.clone());
        calldata.push(pd.r_aux_y.clone());

        // Range proof
        let range: krusty_kms_common::Range = match serde_json::from_str(&pd.range_json) {
            Ok(r) => r,
            Err(_) => return KMS_ERR_JSON,
        };
        let range_felts = match serialization::serialize_range(&range).map_err(|_| KMS_ERR_CRYPTO) {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.extend(felts_to_hex_vec(&range_felts));

        if let Err(e) = append_audit_option(&mut calldata, pd.audit_json.as_deref()) {
            return e;
        }

        let call = CallJson {
            to: params.tongo_address,
            selector: felt_hex(&selector("withdraw")),
            calldata,
        };

        match build_calls_json(vec![call]) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Ragequit calls
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EncodeRagequitParams {
    tongo_address: String,
    proof_result_json: String,
    hint_ciphertext_hex: String,
    hint_nonce_hex: String,
}

#[derive(Deserialize)]
struct RagequitProofData {
    y_x: String,
    y_y: String,
    a_x_x: String,
    a_x_y: String,
    a_r_x: String,
    a_r_y: String,
    sx: String,
    amount: String,
    recipient: String,
    audit_json: Option<String>,
}

#[no_mangle]
pub unsafe extern "C" fn kms_encode_ragequit_calls(
    params_json: *const c_char,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let json_str = match crate::helpers::read_cstr(params_json) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let params: EncodeRagequitParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };
        let pd: RagequitProofData = match serde_json::from_str(&params.proof_result_json) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let amount: u128 = match pd.amount.parse() {
            Ok(a) => a,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };

        let mut calldata = vec![
            // from (public key)
            pd.y_x.clone(),
            pd.y_y.clone(),
            // to (recipient)
            pd.recipient.clone(),
            // amount
            felt_hex(&Felt::from(amount)),
        ];

        // Hint
        if let Err(e) = append_hint_felts(
            &mut calldata,
            &params.hint_ciphertext_hex,
            &params.hint_nonce_hex,
        ) {
            return e;
        }

        // Proof: Ax, Ar, sx
        calldata.push(pd.a_x_x.clone());
        calldata.push(pd.a_x_y.clone());
        calldata.push(pd.a_r_x.clone());
        calldata.push(pd.a_r_y.clone());
        calldata.push(pd.sx.clone());

        if let Err(e) = append_audit_option(&mut calldata, pd.audit_json.as_deref()) {
            return e;
        }

        let call = CallJson {
            to: params.tongo_address,
            selector: felt_hex(&selector("ragequit")),
            calldata,
        };

        match build_calls_json(vec![call]) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{
        kms_account_create_from_keys, kms_account_destroy, kms_account_update_state,
    };
    use crate::error::KMS_OK;
    use crate::helpers::{felt_hex_fixed, felt_to_kms};
    use crate::json_types::JsonCiphertext;
    use crate::proof::{
        kms_generate_ragequit_proof, kms_generate_transfer_proof, kms_generate_withdraw_proof,
    };
    use crate::types::{KmsAccountHandle, KmsAccountState};
    use krusty_kms_common::{ProofOfTransfer, Range};
    use krusty_kms_crypto::StarkCurve;
    use serde::Deserialize;
    use serde_json::json;
    use starknet_types_core::felt::Felt;
    use std::ffi::{c_char, CString};

    struct TestAccount {
        handle: KmsAccountHandle,
        contract_address: Felt,
        chain_id: Felt,
        current_cipher: JsonCiphertext,
        auditor_public_key: String,
        recipient_public_key: String,
    }

    impl Drop for TestAccount {
        fn drop(&mut self) {
            let _ = unsafe { kms_account_destroy(self.handle) };
        }
    }

    #[derive(Deserialize)]
    struct EncodedCall {
        calldata: Vec<String>,
    }

    #[derive(Deserialize)]
    struct EncodedCalls {
        calls: Vec<EncodedCall>,
    }

    fn u128_to_pair(v: u128) -> (u64, u64) {
        (v as u64, (v >> 64) as u64)
    }

    fn point_hex_xy(p: &starknet_types_core::curve::ProjectivePoint) -> (String, String) {
        let a = StarkCurve::projective_to_affine(p).unwrap();
        (felt_hex_fixed(&a.x()), felt_hex_fixed(&a.y()))
    }

    fn point_hex_concat_xy(p: &starknet_types_core::curve::ProjectivePoint) -> String {
        let a = StarkCurve::projective_to_affine(p).unwrap();
        format!("0x{:064x}{:064x}", a.x(), a.y())
    }

    fn make_cipher(
        balance: u128,
        owner_public_key: &starknet_types_core::curve::ProjectivePoint,
    ) -> JsonCiphertext {
        let g = StarkCurve::generator();
        let random = Felt::from(42u64);
        let g_m = StarkCurve::mul(&Felt::from(balance), Some(&g));
        let pk_r = StarkCurve::mul(&random, Some(owner_public_key));
        let l = StarkCurve::add(&g_m, &pk_r);
        let r = StarkCurve::mul(&random, Some(&g));
        let (l_x, l_y) = point_hex_xy(&l);
        let (r_x, r_y) = point_hex_xy(&r);
        JsonCiphertext { l_x, l_y, r_x, r_y }
    }

    fn create_test_account(balance: u128) -> TestAccount {
        let contract_address = Felt::from(123456u64);
        let chain_id = Felt::from_hex("0x534e5f5345504f4c4941").unwrap(); // SN_SEPOLIA
        let contract_addr_kms = felt_to_kms(&contract_address);
        let owner_private_key = Felt::from(42u64);
        let view_private_key = Felt::from(123u64);
        let owner_key_kms = felt_to_kms(&owner_private_key);
        let view_key_kms = felt_to_kms(&view_private_key);

        let mut handle: KmsAccountHandle = 0;
        let rc = unsafe {
            kms_account_create_from_keys(
                &owner_key_kms,
                &view_key_kms,
                &contract_addr_kms,
                &mut handle,
            )
        };
        assert_eq!(rc, KMS_OK);

        let (balance_low, balance_high) = u128_to_pair(balance);
        let state = KmsAccountState {
            balance_low,
            balance_high,
            pending_balance_low: 0,
            pending_balance_high: 0,
            nonce: 0,
        };
        let rc = unsafe { kms_account_update_state(handle, &state) };
        assert_eq!(rc, KMS_OK);

        let owner_public_key = StarkCurve::mul_generator(&owner_private_key);
        let current_cipher = make_cipher(balance, &owner_public_key);

        let auditor_public_key =
            point_hex_concat_xy(&StarkCurve::mul_generator(&Felt::from(777u64)));
        let recipient_public_key =
            point_hex_concat_xy(&StarkCurve::mul_generator(&Felt::from(99u64)));

        TestAccount {
            handle,
            contract_address,
            chain_id,
            current_cipher,
            auditor_public_key,
            recipient_public_key,
        }
    }

    unsafe fn call_proof_endpoint(
        f: unsafe extern "C" fn(
            KmsAccountHandle,
            *const c_char,
            *mut c_char,
            usize,
            *mut usize,
        ) -> i32,
        handle: KmsAccountHandle,
        params_json: &str,
    ) -> String {
        let params = CString::new(params_json).unwrap();

        let mut needed = 0usize;
        let rc = f(
            handle,
            params.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        assert_eq!(rc, KMS_OK);
        assert!(needed > 0);

        let mut buf = vec![0u8; needed + 1];
        let mut written = 0usize;
        let rc = f(
            handle,
            params.as_ptr(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut written,
        );
        assert_eq!(rc, KMS_OK);
        assert_eq!(written, needed);
        String::from_utf8(buf[..written].to_vec()).unwrap()
    }

    unsafe fn call_encode_endpoint(
        f: unsafe extern "C" fn(*const c_char, *mut c_char, usize, *mut usize) -> i32,
        params_json: &str,
    ) -> String {
        let params = CString::new(params_json).unwrap();

        let mut needed = 0usize;
        let rc = f(params.as_ptr(), std::ptr::null_mut(), 0, &mut needed);
        assert_eq!(rc, KMS_OK);
        assert!(needed > 0);

        let mut buf = vec![0u8; needed + 1];
        let mut written = 0usize;
        let rc = f(
            params.as_ptr(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut written,
        );
        assert_eq!(rc, KMS_OK);
        assert_eq!(written, needed);

        String::from_utf8(buf[..written].to_vec()).unwrap()
    }

    fn generator_xy_hex() -> (String, String) {
        let g = StarkCurve::generator();
        let affine = StarkCurve::projective_to_affine(&g).unwrap();
        (format!("{:#x}", affine.x()), format!("{:#x}", affine.y()))
    }

    fn sample_audit_json() -> String {
        let (x, y) = generator_xy_hex();
        serde_json::json!({
            "audited_balance": {
                "l": {"x": x.clone(), "y": y.clone()},
                "r": {"x": x.clone(), "y": y.clone()}
            },
            "hint_ciphertext": hex::encode([0u8; 64]),
            "hint_nonce": hex::encode([0u8; 24]),
            "proof": {
                "Ax": {"x": x.clone(), "y": y.clone()},
                "AL0": {"x": x.clone(), "y": y.clone()},
                "AL1": {"x": x.clone(), "y": y.clone()},
                "AR1": {"x": x, "y": y},
                "sx": "0x1",
                "sb": "0x2",
                "sr": "0x3",
                "c": "0x4"
            }
        })
        .to_string()
    }

    #[test]
    fn append_audit_none_writes_option_tag_only() {
        let mut calldata = Vec::new();
        append_audit_option(&mut calldata, None).unwrap();
        assert_eq!(calldata, vec!["0x1"]);
    }

    #[test]
    fn append_audit_some_serializes_payload() {
        let mut calldata = Vec::new();
        let audit_json = sample_audit_json();
        append_audit_option(&mut calldata, Some(&audit_json)).unwrap();

        assert_eq!(calldata[0], "0x0");
        assert_eq!(calldata.len(), 1 + 4 + 6 + 11); // Option tag + balance + hint + proof
    }

    #[test]
    fn fund_calls_overflow_returns_invalid_input() {
        let (x, y) = generator_xy_hex();
        let proof_json = serde_json::json!({
            "A": {"x": x, "y": y},
            "s": "0x1",
            "c": "0x2"
        })
        .to_string();

        let proof_result_json = serde_json::json!({
            "y_x": "0x1",
            "y_y": "0x2",
            "proof_json": proof_json,
            "amount": u128::MAX.to_string(),
            "audit_json": null
        })
        .to_string();

        let params_json = serde_json::json!({
            "tongo_address": "0x1",
            "erc20_address": "0x2",
            "rate": "2",
            "proof_result_json": proof_result_json,
            "hint_ciphertext_hex": hex::encode([0u8; 64]),
            "hint_nonce_hex": hex::encode([0u8; 24])
        })
        .to_string();

        let params_c = CString::new(params_json).unwrap();
        let rc = unsafe {
            kms_encode_fund_calls(
                params_c.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, KMS_ERR_INVALID_INPUT);
    }

    #[test]
    fn transfer_calldata_encodes_both_audit_some_variants() {
        let account = create_test_account(1000);

        let proof_params = json!({
            "recipient_public_key": account.recipient_public_key,
            "amount": "100",
            "nonce": felt_hex_fixed(&Felt::from(2u64)),
            "chain_id": felt_hex_fixed(&account.chain_id),
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "current_cipher": &account.current_cipher,
            "bit_size": 16,
            "auditor_public_key": account.auditor_public_key,
        })
        .to_string();

        let proof_result_json = unsafe {
            call_proof_endpoint(kms_generate_transfer_proof, account.handle, &proof_params)
        };
        let proof_result: serde_json::Value = serde_json::from_str(&proof_result_json).unwrap();
        assert!(proof_result["audit_balance_json"].is_string());
        assert!(proof_result["audit_transfer_json"].is_string());

        let encode_params = json!({
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "proof_result_json": proof_result_json,
            "hint_ciphertext_hex": hex::encode([0u8; 64]),
            "hint_nonce_hex": hex::encode([0u8; 24]),
        })
        .to_string();
        let encoded_json =
            unsafe { call_encode_endpoint(kms_encode_transfer_calls, &encode_params) };
        let encoded: EncodedCalls = serde_json::from_str(&encoded_json).unwrap();

        assert_eq!(encoded.calls.len(), 1);
        let calldata = &encoded.calls[0].calldata;

        let proof_json = proof_result["proof_json"].as_str().unwrap();
        let proof: ProofOfTransfer = serde_json::from_str(proof_json).unwrap();
        let proof_len = krusty_kms_sdk::serialization::serialize_proof_of_transfer(&proof)
            .unwrap()
            .len();

        let base_len = 8 + 6 + proof_len;
        let audit_some_len = 1 + 4 + 6 + 11;
        assert_eq!(calldata[base_len], "0x0");
        assert_eq!(calldata[base_len + audit_some_len], "0x0");
        assert_eq!(calldata.len(), base_len + audit_some_len + audit_some_len);
    }

    #[test]
    fn withdraw_calldata_encodes_audit_some_variant() {
        let account = create_test_account(1000);

        let proof_params = json!({
            "recipient_address": felt_hex_fixed(&Felt::from(999u64)),
            "amount": "100",
            "nonce": felt_hex_fixed(&Felt::from(4u64)),
            "chain_id": felt_hex_fixed(&account.chain_id),
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "current_cipher": &account.current_cipher,
            "bit_size": 16,
            "auditor_public_key": account.auditor_public_key,
        })
        .to_string();
        let proof_result_json = unsafe {
            call_proof_endpoint(kms_generate_withdraw_proof, account.handle, &proof_params)
        };
        let proof_result: serde_json::Value = serde_json::from_str(&proof_result_json).unwrap();
        assert!(proof_result["audit_json"].is_string());

        let encode_params = json!({
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "proof_result_json": proof_result_json,
            "hint_ciphertext_hex": hex::encode([0u8; 64]),
            "hint_nonce_hex": hex::encode([0u8; 24]),
        })
        .to_string();
        let encoded_json =
            unsafe { call_encode_endpoint(kms_encode_withdraw_calls, &encode_params) };
        let encoded: EncodedCalls = serde_json::from_str(&encoded_json).unwrap();

        assert_eq!(encoded.calls.len(), 1);
        let calldata = &encoded.calls[0].calldata;

        let range_json = proof_result["range_json"].as_str().unwrap();
        let range: Range = serde_json::from_str(range_json).unwrap();
        let range_len = krusty_kms_sdk::serialization::serialize_range(&range)
            .unwrap()
            .len();

        let base_len = 23 + range_len;
        let audit_some_len = 1 + 4 + 6 + 11;
        assert_eq!(calldata[base_len], "0x0");
        assert_eq!(calldata.len(), base_len + audit_some_len);
    }

    #[test]
    fn ragequit_calldata_encodes_audit_some_variant() {
        let account = create_test_account(1000);

        let proof_params = json!({
            "recipient_address": felt_hex_fixed(&Felt::from(999u64)),
            "nonce": felt_hex_fixed(&Felt::from(5u64)),
            "chain_id": felt_hex_fixed(&account.chain_id),
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "current_cipher": &account.current_cipher,
            "auditor_public_key": account.auditor_public_key,
        })
        .to_string();
        let proof_result_json = unsafe {
            call_proof_endpoint(kms_generate_ragequit_proof, account.handle, &proof_params)
        };
        let proof_result: serde_json::Value = serde_json::from_str(&proof_result_json).unwrap();
        assert!(proof_result["audit_json"].is_string());

        let encode_params = json!({
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "proof_result_json": proof_result_json,
            "hint_ciphertext_hex": hex::encode([0u8; 64]),
            "hint_nonce_hex": hex::encode([0u8; 24]),
        })
        .to_string();
        let encoded_json =
            unsafe { call_encode_endpoint(kms_encode_ragequit_calls, &encode_params) };
        let encoded: EncodedCalls = serde_json::from_str(&encoded_json).unwrap();

        assert_eq!(encoded.calls.len(), 1);
        let calldata = &encoded.calls[0].calldata;

        let base_len = 15;
        let audit_some_len = 1 + 4 + 6 + 11;
        assert_eq!(calldata[base_len], "0x0");
        assert_eq!(calldata.len(), base_len + audit_some_len);
    }
}
