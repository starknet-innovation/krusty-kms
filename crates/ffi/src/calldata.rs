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

use krusty_kms_common::{AuditCalldata, AuditProof, ElGamalCiphertext, PoeProof, ProofOfTransfer};
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
    let mut out = [u8::default(); N];
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
            let l = parse_projective_point(&audit.audited_balance.l.x, &audit.audited_balance.l.y)?;
            let r = parse_projective_point(&audit.audited_balance.r.x, &audit.audited_balance.r.y)?;
            let hint_ciphertext = decode_hex_bytes::<64>(&audit.hint_ciphertext)?;
            let hint_nonce = decode_hex_bytes::<24>(&audit.hint_nonce)?;
            let felts = serialization::serialize_audit_option(Some(AuditCalldata {
                audited_balance: &ElGamalCiphertext { l, r },
                hint_ciphertext: &hint_ciphertext,
                hint_nonce: &hint_nonce,
                proof: &audit.proof,
            }))
            .map_err(|_| KMS_ERR_CRYPTO)?;
            calldata.extend(felts_to_hex_vec(&felts));
            Ok(())
        }
        None => {
            let felts = serialization::serialize_audit_option(None).map_err(|_| KMS_ERR_CRYPTO)?;
            calldata.extend(felts_to_hex_vec(&felts));
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

/// Input for [`kms_encode_transfer_calls`].
///
/// `sender_public_key` and `recipient_public_key` use the same
/// `0x` + 64-hex `x` + 64-hex `y` form as `recipient_public_key` in the
/// transfer proof parameters. `hint_ciphertext_hex` / `hint_nonce_hex` carry
/// the recipient's `hintTransfer`; `hint_leftover_*` carry the sender's
/// `hintLeftover`. Every field is required.
#[derive(Deserialize)]
struct EncodeTransferParams {
    tongo_address: String,
    sender_public_key: String,
    recipient_public_key: String,
    proof_result_json: String,
    hint_ciphertext_hex: String,
    hint_nonce_hex: String,
    hint_leftover_ciphertext_hex: String,
    hint_leftover_nonce_hex: String,
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
    aux_v_x: String,
    aux_v_y: String,
    aux_r_x: String,
    aux_r_y: String,
    aux2_v_x: String,
    aux2_v_y: String,
    aux2_r_x: String,
    aux2_r_y: String,
    proof_json: String,
    audit_balance_json: Option<String>,
    audit_transfer_json: Option<String>,
}

/// Append a Tongo public key (`0x` + 64-hex `x` + 64-hex `y`) as `PubKey`
/// calldata: two felts, `x` then `y`.
fn append_public_key_felts(calldata: &mut Vec<String>, public_key_hex: &str) -> Result<(), i32> {
    let point = crate::proof::parse_public_key(public_key_hex)?;
    let (x, y) =
        serialization::serialize_projective_point(&point).map_err(|_| KMS_ERR_INVALID_INPUT)?;
    calldata.push(felt_hex(&x));
    calldata.push(felt_hex(&y));
    Ok(())
}

/// Serialize the Cairo `Transfer` struct in the contract's field order:
/// `from`, `to`, `transferBalance`, `transferBalanceSelf`, `hintTransfer`,
/// `hintLeftover`, `auxiliarCipher`, `auxiliarCipher2`, `proof`, `auditPart`,
/// `auditPartTransfer`.
///
/// This is the layout `krusty_kms_client::build_transfer_call` emits; the two
/// must not drift.
fn transfer_calldata(
    params: &EncodeTransferParams,
    proof_data: &TransferProofData,
) -> Result<Vec<String>, i32> {
    let mut calldata = Vec::new();

    // 1-2. from, to
    append_public_key_felts(&mut calldata, &params.sender_public_key)?;
    append_public_key_felts(&mut calldata, &params.recipient_public_key)?;

    // 3-4. transferBalance, transferBalanceSelf: L, R each
    for (x, y) in [
        (&proof_data.transfer_l_x, &proof_data.transfer_l_y),
        (&proof_data.transfer_r_x, &proof_data.transfer_r_y),
        (&proof_data.self_l_x, &proof_data.self_l_y),
        (&proof_data.self_r_x, &proof_data.self_r_y),
    ] {
        calldata.push(felt_hex(&parse_felt(x)?));
        calldata.push(felt_hex(&parse_felt(y)?));
    }

    // 5-6. hintTransfer, hintLeftover
    append_hint_felts(
        &mut calldata,
        &params.hint_ciphertext_hex,
        &params.hint_nonce_hex,
    )?;
    append_hint_felts(
        &mut calldata,
        &params.hint_leftover_ciphertext_hex,
        &params.hint_leftover_nonce_hex,
    )?;

    // 7-8. auxiliarCipher (V, R_aux for transfer amount), auxiliarCipher2 (leftover)
    for hex_val in [
        &proof_data.aux_v_x,
        &proof_data.aux_v_y,
        &proof_data.aux_r_x,
        &proof_data.aux_r_y,
        &proof_data.aux2_v_x,
        &proof_data.aux2_v_y,
        &proof_data.aux2_r_x,
        &proof_data.aux2_r_y,
    ] {
        calldata.push(hex_val.clone());
    }

    // 9. proof (serialized as JSON, contains all commitments and range proofs)
    let transfer_proof: ProofOfTransfer =
        serde_json::from_str(&proof_data.proof_json).map_err(|_| KMS_ERR_JSON)?;
    let proof_felts =
        serialization::serialize_proof_of_transfer(&transfer_proof).map_err(|_| KMS_ERR_CRYPTO)?;
    calldata.extend(felts_to_hex_vec(&proof_felts));

    // 10-11. auditPart, auditPartTransfer
    append_audit_option(&mut calldata, proof_data.audit_balance_json.as_deref())?;
    append_audit_option(&mut calldata, proof_data.audit_transfer_json.as_deref())?;

    Ok(calldata)
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

        let calldata = match transfer_calldata(&params, &proof_data) {
            Ok(c) => c,
            Err(e) => return e,
        };

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
    v_aux_x: String,
    v_aux_y: String,
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

        // Auxiliary cipher (V.x, V.y, R_aux.x, R_aux.y) — before proof fields
        calldata.push(pd.v_aux_x.clone());
        calldata.push(pd.v_aux_y.clone());
        calldata.push(pd.r_aux_x.clone());
        calldata.push(pd.r_aux_y.clone());

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
mod tests;
