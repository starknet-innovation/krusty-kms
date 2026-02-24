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

use krusty_kms_common::{PoeProof, ProofOfTransfer};
use krusty_kms_sdk::serialization;
use serde::{Deserialize, Serialize};
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
        let approve_amount = amount * rate;
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
        let hint_ct = match hex::decode(&params.hint_ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        let hint_nonce = match hex::decode(&params.hint_nonce_hex) {
            Ok(b) => b,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        if hint_ct.len() != 64 || hint_nonce.len() != 24 {
            return KMS_ERR_INVALID_INPUT;
        }
        let mut ct_arr = [0u8; 64];
        let mut nonce_arr = [0u8; 24];
        ct_arr.copy_from_slice(&hint_ct);
        nonce_arr.copy_from_slice(&hint_nonce);

        let hint_felts = match serialize_ae_balance_felts(&ct_arr, &nonce_arr) {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.extend(felts_to_hex_vec(&hint_felts));

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
        if proof_data.audit_json.is_some() {
            // TODO: full audit serialization
            calldata.push(felt_hex(&Felt::ZERO)); // Some variant
                                                  // Audit data would be parsed and serialized here
        } else {
            calldata.push(felt_hex(&Felt::ONE)); // None variant
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
        let hint_ct = match hex::decode(&params.hint_ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        let hint_nonce = match hex::decode(&params.hint_nonce_hex) {
            Ok(b) => b,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        if hint_ct.len() != 64 || hint_nonce.len() != 24 {
            return KMS_ERR_INVALID_INPUT;
        }
        let mut ct_arr = [0u8; 64];
        let mut nonce_arr = [0u8; 24];
        ct_arr.copy_from_slice(&hint_ct);
        nonce_arr.copy_from_slice(&hint_nonce);

        let hint_felts = match serialize_ae_balance_felts(&ct_arr, &nonce_arr) {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.extend(felts_to_hex_vec(&hint_felts));

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
        let hint_ct = match hex::decode(&params.hint_ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        let hint_nonce = match hex::decode(&params.hint_nonce_hex) {
            Ok(b) => b,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        if hint_ct.len() != 64 || hint_nonce.len() != 24 {
            return KMS_ERR_INVALID_INPUT;
        }
        let mut ct_arr = [0u8; 64];
        let mut nonce_arr = [0u8; 24];
        ct_arr.copy_from_slice(&hint_ct);
        nonce_arr.copy_from_slice(&hint_nonce);
        let hint_felts = match serialize_ae_balance_felts(&ct_arr, &nonce_arr) {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.extend(felts_to_hex_vec(&hint_felts));

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

        // Audit (None for now)
        calldata.push(felt_hex(&Felt::ONE)); // None

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
        let hint_ct = match hex::decode(&params.hint_ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        let hint_nonce = match hex::decode(&params.hint_nonce_hex) {
            Ok(b) => b,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        if hint_ct.len() != 64 || hint_nonce.len() != 24 {
            return KMS_ERR_INVALID_INPUT;
        }
        let mut ct_arr = [0u8; 64];
        let mut nonce_arr = [0u8; 24];
        ct_arr.copy_from_slice(&hint_ct);
        nonce_arr.copy_from_slice(&hint_nonce);
        let hint_felts = match serialize_ae_balance_felts(&ct_arr, &nonce_arr) {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.extend(felts_to_hex_vec(&hint_felts));

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

        // Audit: None
        calldata.push(felt_hex(&Felt::ONE));

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
        let hint_ct = match hex::decode(&params.hint_ciphertext_hex) {
            Ok(b) => b,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        let hint_nonce = match hex::decode(&params.hint_nonce_hex) {
            Ok(b) => b,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        if hint_ct.len() != 64 || hint_nonce.len() != 24 {
            return KMS_ERR_INVALID_INPUT;
        }
        let mut ct_arr = [0u8; 64];
        let mut nonce_arr = [0u8; 24];
        ct_arr.copy_from_slice(&hint_ct);
        nonce_arr.copy_from_slice(&hint_nonce);
        let hint_felts = match serialize_ae_balance_felts(&ct_arr, &nonce_arr) {
            Ok(f) => f,
            Err(e) => return e,
        };
        calldata.extend(felts_to_hex_vec(&hint_felts));

        // Proof: Ax, Ar, sx
        calldata.push(pd.a_x_x.clone());
        calldata.push(pd.a_x_y.clone());
        calldata.push(pd.a_r_x.clone());
        calldata.push(pd.a_r_y.clone());
        calldata.push(pd.sx.clone());

        // Audit: None
        calldata.push(felt_hex(&Felt::ONE));

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
