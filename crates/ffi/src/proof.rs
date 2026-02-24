//! Proof generation FFI functions.
//!
//! Each function follows the same pattern:
//! 1. Parse JSON params from the C string
//! 2. Convert to SDK param types
//! 3. Call the SDK operation
//! 4. Serialize the result to JSON
//! 5. Write to the output buffer via the two-call pattern

use std::ffi::c_char;
use std::panic::catch_unwind;

use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_sdk::operations::{
    fund, ragequit, rollover, transfer, withdraw, FundParams, RagequitParams, RolloverParams,
    TransferParams, WithdrawParams,
};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

use crate::error::*;
use crate::handle;
use crate::helpers::write_string_output;
use crate::json_types::*;
use crate::types::KmsAccountHandle;

/// Default bit size for range proofs (40 bits = ~1 trillion max).
const DEFAULT_BIT_SIZE: usize = 40;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn parse_felt(hex: &str) -> Result<Felt, i32> {
    Felt::from_hex(hex).map_err(|_| KMS_ERR_INVALID_INPUT)
}

fn parse_public_key(hex: &str) -> Result<ProjectivePoint, i32> {
    let hex = hex.trim();
    if (hex.starts_with("0x") || hex.starts_with("0X")) && hex.len() == 130 {
        let hex_data = &hex[2..];
        let x_hex = format!("0x{}", &hex_data[..64]);
        let y_hex = format!("0x{}", &hex_data[64..]);
        let x = Felt::from_hex(&x_hex).map_err(|_| KMS_ERR_INVALID_INPUT)?;
        let y = Felt::from_hex(&y_hex).map_err(|_| KMS_ERR_INVALID_INPUT)?;
        ProjectivePoint::from_affine(x, y).map_err(|_| KMS_ERR_INVALID_INPUT)
    } else {
        Err(KMS_ERR_INVALID_INPUT)
    }
}

fn parse_ciphertext(c: &JsonCiphertext) -> Result<ElGamalCiphertext, i32> {
    let lx = parse_felt(&c.l_x)?;
    let ly = parse_felt(&c.l_y)?;
    let rx = parse_felt(&c.r_x)?;
    let ry = parse_felt(&c.r_y)?;
    let l = ProjectivePoint::from_affine(lx, ly).map_err(|_| KMS_ERR_INVALID_INPUT)?;
    let r = ProjectivePoint::from_affine(rx, ry).map_err(|_| KMS_ERR_INVALID_INPUT)?;
    Ok(ElGamalCiphertext { l, r })
}

fn point_to_hex_xy(p: &ProjectivePoint) -> Result<(String, String), i32> {
    let a = p.to_affine().map_err(|_| KMS_ERR_CRYPTO)?;
    Ok((format!("{:#x}", a.x()), format!("{:#x}", a.y())))
}

fn serialize_audit(audit: &krusty_kms_sdk::operations::Audit) -> Result<String, i32> {
    let l_a = audit
        .audited_balance
        .l
        .to_affine()
        .map_err(|_| KMS_ERR_CRYPTO)?;
    let r_a = audit
        .audited_balance
        .r
        .to_affine()
        .map_err(|_| KMS_ERR_CRYPTO)?;

    let json = serde_json::json!({
        "audited_balance": {
            "l": { "x": format!("{:#x}", l_a.x()), "y": format!("{:#x}", l_a.y()) },
            "r": { "x": format!("{:#x}", r_a.x()), "y": format!("{:#x}", r_a.y()) }
        },
        "hint_ciphertext": hex::encode(audit.hint_ciphertext),
        "hint_nonce": hex::encode(audit.hint_nonce),
        "proof": &audit.proof
    });

    serde_json::to_string(&json).map_err(|_| KMS_ERR_JSON)
}

// ---------------------------------------------------------------------------
// Fund proof
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_generate_fund_proof(
    h: KmsAccountHandle,
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

        let params: JsonFundParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let amount: u128 = match params.amount.parse() {
            Ok(a) => a,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };

        let current_balance = match parse_ciphertext(&params.current_cipher) {
            Ok(c) => c,
            Err(e) => return e,
        };

        let auditor_pub_key = match params
            .auditor_public_key
            .as_ref()
            .map(|pk| parse_public_key(pk))
            .transpose()
        {
            Ok(a) => a,
            Err(e) => return e,
        };

        let sdk_params = FundParams {
            amount,
            nonce: match parse_felt(&params.nonce) {
                Ok(f) => f,
                Err(e) => return e,
            },
            chain_id: match parse_felt(&params.chain_id) {
                Ok(f) => f,
                Err(e) => return e,
            },
            tongo_address: match parse_felt(&params.tongo_address) {
                Ok(f) => f,
                Err(e) => return e,
            },
            auditor_pub_key,
            current_balance,
        };

        let result = handle::with(h, |acc| fund(acc, sdk_params).map_err(|_| KMS_ERR_CRYPTO));

        let proof = match result {
            Ok(p) => p,
            Err(e) => return e,
        };

        let (y_x, y_y) = match point_to_hex_xy(&proof.y) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let proof_json_str = match serde_json::to_string(&proof.proof) {
            Ok(s) => s,
            Err(_) => return KMS_ERR_JSON,
        };

        let audit_json = match proof.audit.as_ref().map(serialize_audit).transpose() {
            Ok(a) => a,
            Err(e) => return e,
        };

        let result = JsonFundResult {
            y_x,
            y_y,
            proof_json: proof_json_str,
            amount: proof.amount.to_string(),
            audit_json,
        };

        match serde_json::to_string(&result) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(_) => KMS_ERR_JSON,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Transfer proof
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_generate_transfer_proof(
    h: KmsAccountHandle,
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

        let params: JsonTransferParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let amount: u128 = match params.amount.parse() {
            Ok(a) => a,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };

        let current_balance = match parse_ciphertext(&params.current_cipher) {
            Ok(c) => c,
            Err(e) => return e,
        };

        let recipient_public_key = match parse_public_key(&params.recipient_public_key) {
            Ok(pk) => pk,
            Err(e) => return e,
        };

        let auditor_pub_key = match params
            .auditor_public_key
            .as_ref()
            .map(|pk| parse_public_key(pk))
            .transpose()
        {
            Ok(a) => a,
            Err(e) => return e,
        };

        let sdk_params = TransferParams {
            recipient_public_key,
            amount,
            nonce: match parse_felt(&params.nonce) {
                Ok(f) => f,
                Err(e) => return e,
            },
            chain_id: match parse_felt(&params.chain_id) {
                Ok(f) => f,
                Err(e) => return e,
            },
            tongo_address: match parse_felt(&params.tongo_address) {
                Ok(f) => f,
                Err(e) => return e,
            },
            current_balance,
            bit_size: params
                .bit_size
                .map(|b| b as usize)
                .unwrap_or(DEFAULT_BIT_SIZE),
            auditor_pub_key,
        };

        let result = handle::with(h, |acc| {
            transfer(acc, sdk_params).map_err(|_| KMS_ERR_CRYPTO)
        });

        let proof = match result {
            Ok(p) => p,
            Err(e) => return e,
        };

        let (tl_x, tl_y) = match point_to_hex_xy(&proof.transfer_balance_l) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (tr_x, tr_y) = match point_to_hex_xy(&proof.transfer_balance_r) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (sl_x, sl_y) = match point_to_hex_xy(&proof.transfer_balance_self_l) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (sr_x, sr_y) = match point_to_hex_xy(&proof.transfer_balance_self_r) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (nl_x, nl_y) = match point_to_hex_xy(&proof.new_balance_cipher.l) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (nr_x, nr_y) = match point_to_hex_xy(&proof.new_balance_cipher.r) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let proof_json_str = match serde_json::to_string(&proof.proof) {
            Ok(s) => s,
            Err(_) => return KMS_ERR_JSON,
        };

        let audit_balance_json = match proof
            .audit_balance
            .as_ref()
            .map(serialize_audit)
            .transpose()
        {
            Ok(a) => a,
            Err(e) => return e,
        };
        let audit_transfer_json = match proof
            .audit_transfer
            .as_ref()
            .map(serialize_audit)
            .transpose()
        {
            Ok(a) => a,
            Err(e) => return e,
        };

        let result = JsonTransferResult {
            transfer_l_x: tl_x,
            transfer_l_y: tl_y,
            transfer_r_x: tr_x,
            transfer_r_y: tr_y,
            self_l_x: sl_x,
            self_l_y: sl_y,
            self_r_x: sr_x,
            self_r_y: sr_y,
            new_balance_l_x: nl_x,
            new_balance_l_y: nl_y,
            new_balance_r_x: nr_x,
            new_balance_r_y: nr_y,
            proof_json: proof_json_str,
            audit_balance_json,
            audit_transfer_json,
        };

        match serde_json::to_string(&result) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(_) => KMS_ERR_JSON,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Rollover proof
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_generate_rollover_proof(
    h: KmsAccountHandle,
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

        let params: JsonRolloverParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let sdk_params = RolloverParams {
            nonce: match parse_felt(&params.nonce) {
                Ok(f) => f,
                Err(e) => return e,
            },
            chain_id: match parse_felt(&params.chain_id) {
                Ok(f) => f,
                Err(e) => return e,
            },
            tongo_address: match parse_felt(&params.tongo_address) {
                Ok(f) => f,
                Err(e) => return e,
            },
        };

        let result = handle::with(h, |acc| {
            rollover(acc, sdk_params).map_err(|_| KMS_ERR_CRYPTO)
        });

        let proof = match result {
            Ok(p) => p,
            Err(e) => return e,
        };

        let (y_x, y_y) = match point_to_hex_xy(&proof.y) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let proof_json_str = match serde_json::to_string(&proof.proof) {
            Ok(s) => s,
            Err(_) => return KMS_ERR_JSON,
        };

        let result = JsonRolloverResult {
            y_x,
            y_y,
            proof_json: proof_json_str,
            pending_amount: proof.pending_amount.to_string(),
        };

        match serde_json::to_string(&result) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(_) => KMS_ERR_JSON,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Withdraw proof
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_generate_withdraw_proof(
    h: KmsAccountHandle,
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

        let params: JsonWithdrawParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let amount: u128 = match params.amount.parse() {
            Ok(a) => a,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };

        let current_balance = match parse_ciphertext(&params.current_cipher) {
            Ok(c) => c,
            Err(e) => return e,
        };

        let auditor_key = match params
            .auditor_public_key
            .as_ref()
            .map(|pk| parse_public_key(pk))
            .transpose()
        {
            Ok(a) => a,
            Err(e) => return e,
        };

        let sdk_params = WithdrawParams {
            recipient_address: match parse_felt(&params.recipient_address) {
                Ok(f) => f,
                Err(e) => return e,
            },
            amount,
            nonce: match parse_felt(&params.nonce) {
                Ok(f) => f,
                Err(e) => return e,
            },
            chain_id: match parse_felt(&params.chain_id) {
                Ok(f) => f,
                Err(e) => return e,
            },
            tongo_address: match parse_felt(&params.tongo_address) {
                Ok(f) => f,
                Err(e) => return e,
            },
            current_balance,
            bit_size: params
                .bit_size
                .map(|b| b as usize)
                .unwrap_or(DEFAULT_BIT_SIZE),
            auditor_key,
        };

        let result = handle::with(h, |acc| {
            withdraw(acc, sdk_params).map_err(|_| KMS_ERR_CRYPTO)
        });

        let proof = match result {
            Ok(p) => p,
            Err(e) => return e,
        };

        let (y_x, y_y) = match point_to_hex_xy(&proof.y) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (ax_x, ax_y) = match point_to_hex_xy(&proof.a_x) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (ar_x, ar_y) = match point_to_hex_xy(&proof.a_r) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (a_x2, a_y2) = match point_to_hex_xy(&proof.a) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (av_x, av_y) = match point_to_hex_xy(&proof.a_v) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (raux_x, raux_y) = match point_to_hex_xy(&proof.r_aux) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let range_json = match serde_json::to_string(&proof.range) {
            Ok(s) => s,
            Err(_) => return KMS_ERR_JSON,
        };

        let audit_json = match proof.audit.as_ref().map(serialize_audit).transpose() {
            Ok(a) => a,
            Err(e) => return e,
        };

        let result = JsonWithdrawResult {
            y_x,
            y_y,
            a_x_x: ax_x,
            a_x_y: ax_y,
            a_r_x: ar_x,
            a_r_y: ar_y,
            a_x2,
            a_y2,
            a_v_x: av_x,
            a_v_y: av_y,
            sx: format!("{:#x}", proof.sx),
            sb: format!("{:#x}", proof.sb),
            sr: format!("{:#x}", proof.sr),
            r_aux_x: raux_x,
            r_aux_y: raux_y,
            range_json,
            amount: proof.amount.to_string(),
            recipient: format!("{:#x}", proof.recipient),
            audit_json,
        };

        match serde_json::to_string(&result) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(_) => KMS_ERR_JSON,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Ragequit proof
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_generate_ragequit_proof(
    h: KmsAccountHandle,
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

        let params: JsonRagequitParams = match serde_json::from_str(json_str) {
            Ok(p) => p,
            Err(_) => return KMS_ERR_JSON,
        };

        let current_balance = match parse_ciphertext(&params.current_cipher) {
            Ok(c) => c,
            Err(e) => return e,
        };

        let auditor_key = match params
            .auditor_public_key
            .as_ref()
            .map(|pk| parse_public_key(pk))
            .transpose()
        {
            Ok(a) => a,
            Err(e) => return e,
        };

        let sdk_params = RagequitParams {
            recipient_address: match parse_felt(&params.recipient_address) {
                Ok(f) => f,
                Err(e) => return e,
            },
            nonce: match parse_felt(&params.nonce) {
                Ok(f) => f,
                Err(e) => return e,
            },
            chain_id: match parse_felt(&params.chain_id) {
                Ok(f) => f,
                Err(e) => return e,
            },
            tongo_address: match parse_felt(&params.tongo_address) {
                Ok(f) => f,
                Err(e) => return e,
            },
            current_balance,
            auditor_key,
        };

        let result = handle::with(h, |acc| {
            ragequit(acc, sdk_params).map_err(|_| KMS_ERR_CRYPTO)
        });

        let proof = match result {
            Ok(p) => p,
            Err(e) => return e,
        };

        let (y_x, y_y) = match point_to_hex_xy(&proof.y) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (ax_x, ax_y) = match point_to_hex_xy(&proof.a_x) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (ar_x, ar_y) = match point_to_hex_xy(&proof.a_r) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let audit_json = match proof.audit.as_ref().map(serialize_audit).transpose() {
            Ok(a) => a,
            Err(e) => return e,
        };

        let result = JsonRagequitResult {
            y_x,
            y_y,
            a_x_x: ax_x,
            a_x_y: ax_y,
            a_r_x: ar_x,
            a_r_y: ar_y,
            sx: format!("{:#x}", proof.sx),
            amount: proof.amount.to_string(),
            recipient: format!("{:#x}", proof.recipient),
            audit_json,
        };

        match serde_json::to_string(&result) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(_) => KMS_ERR_JSON,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}
