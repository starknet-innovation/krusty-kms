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
use crate::helpers::{felt_hex_fixed, to_deterministic_json, write_string_output};
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
    Ok((felt_hex_fixed(&a.x()), felt_hex_fixed(&a.y())))
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
            "l": { "x": felt_hex_fixed(&l_a.x()), "y": felt_hex_fixed(&l_a.y()) },
            "r": { "x": felt_hex_fixed(&r_a.x()), "y": felt_hex_fixed(&r_a.y()) }
        },
        "hint_ciphertext": hex::encode(audit.hint_ciphertext),
        "hint_nonce": hex::encode(audit.hint_nonce),
        "proof": &audit.proof
    });

    to_deterministic_json(&json)
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
            sender_address: match parse_felt(&params.sender_address) {
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

        let proof_json_str = match to_deterministic_json(&proof.proof) {
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
            sender_address: match parse_felt(&params.sender_address) {
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
        let (aux_v_x, aux_v_y) = match point_to_hex_xy(&proof.auxiliar_cipher.l) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (aux_r_x, aux_r_y) = match point_to_hex_xy(&proof.auxiliar_cipher.r) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (aux2_v_x, aux2_v_y) = match point_to_hex_xy(&proof.auxiliar_cipher2.l) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (aux2_r_x, aux2_r_y) = match point_to_hex_xy(&proof.auxiliar_cipher2.r) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let proof_json_str = match to_deterministic_json(&proof.proof) {
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
            aux_v_x,
            aux_v_y,
            aux_r_x,
            aux_r_y,
            aux2_v_x,
            aux2_v_y,
            aux2_r_x,
            aux2_r_y,
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
            sender_address: match parse_felt(&params.sender_address) {
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

        let proof_json_str = match to_deterministic_json(&proof.proof) {
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
            sender_address: match parse_felt(&params.sender_address) {
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
        let (vaux_x, vaux_y) = match point_to_hex_xy(&proof.auxiliar_cipher.l) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (raux_x, raux_y) = match point_to_hex_xy(&proof.auxiliar_cipher.r) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let range_json = match to_deterministic_json(&proof.range) {
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
            sx: felt_hex_fixed(&proof.sx),
            sb: felt_hex_fixed(&proof.sb),
            sr: felt_hex_fixed(&proof.sr),
            v_aux_x: vaux_x,
            v_aux_y: vaux_y,
            r_aux_x: raux_x,
            r_aux_y: raux_y,
            range_json,
            amount: proof.amount.to_string(),
            recipient: felt_hex_fixed(&proof.recipient),
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
            sender_address: match parse_felt(&params.sender_address) {
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
            sx: felt_hex_fixed(&proof.sx),
            amount: proof.amount.to_string(),
            recipient: felt_hex_fixed(&proof.recipient),
            audit_json,
        };

        match serde_json::to_string(&result) {
            Ok(s) => write_string_output(&s, out, out_len, out_written),
            Err(_) => KMS_ERR_JSON,
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
    use crate::helpers::{felt_hex_fixed, felt_to_kms};
    use crate::json_types::JsonCiphertext;
    use crate::types::{KmsAccountHandle, KmsAccountState};
    use krusty_kms_crypto::StarkCurve;
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
            // Best-effort cleanup for global registry.
            let _ = unsafe { kms_account_destroy(self.handle) };
        }
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

    unsafe fn assert_two_call_stable(
        f: unsafe extern "C" fn(
            KmsAccountHandle,
            *const c_char,
            *mut c_char,
            usize,
            *mut usize,
        ) -> i32,
        handle: KmsAccountHandle,
        params_json: &str,
    ) {
        let params = CString::new(params_json).unwrap();

        let mut needed1 = 0usize;
        let rc = f(
            handle,
            params.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut needed1,
        );
        assert_eq!(rc, KMS_OK);
        assert!(needed1 > 0);

        let mut needed2 = 0usize;
        let rc = f(
            handle,
            params.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut needed2,
        );
        assert_eq!(rc, KMS_OK);
        assert_eq!(needed2, needed1);

        let mut buf = vec![0u8; needed1 + 1];
        let mut written = 0usize;
        let rc = f(
            handle,
            params.as_ptr(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut written,
        );
        assert_eq!(rc, KMS_OK);
        assert_eq!(written, needed1);

        let json = std::str::from_utf8(&buf[..written]).unwrap();
        let _: serde_json::Value = serde_json::from_str(json).unwrap();
    }

    #[test]
    fn proof_endpoints_two_call_pattern_is_stable() {
        let account = create_test_account(1000);

        let fund_params = json!({
            "amount": "50",
            "nonce": felt_hex_fixed(&Felt::from(1u64)),
            "chain_id": felt_hex_fixed(&account.chain_id),
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "sender_address": felt_hex_fixed(&account.contract_address),
            "current_cipher": &account.current_cipher,
            "auditor_public_key": account.auditor_public_key,
        })
        .to_string();
        unsafe { assert_two_call_stable(kms_generate_fund_proof, account.handle, &fund_params) };

        let transfer_params = json!({
            "recipient_public_key": account.recipient_public_key,
            "amount": "100",
            "nonce": felt_hex_fixed(&Felt::from(2u64)),
            "chain_id": felt_hex_fixed(&account.chain_id),
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "sender_address": felt_hex_fixed(&account.contract_address),
            "current_cipher": &account.current_cipher,
            "bit_size": 16,
            "auditor_public_key": account.auditor_public_key,
        })
        .to_string();
        unsafe {
            assert_two_call_stable(
                kms_generate_transfer_proof,
                account.handle,
                &transfer_params,
            )
        };

        let rollover_params = json!({
            "nonce": felt_hex_fixed(&Felt::from(3u64)),
            "chain_id": felt_hex_fixed(&account.chain_id),
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "sender_address": felt_hex_fixed(&account.contract_address),
        })
        .to_string();
        unsafe {
            assert_two_call_stable(
                kms_generate_rollover_proof,
                account.handle,
                &rollover_params,
            )
        };

        let withdraw_params = json!({
            "recipient_address": felt_hex_fixed(&Felt::from(999u64)),
            "amount": "100",
            "nonce": felt_hex_fixed(&Felt::from(4u64)),
            "chain_id": felt_hex_fixed(&account.chain_id),
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "sender_address": felt_hex_fixed(&account.contract_address),
            "current_cipher": &account.current_cipher,
            "bit_size": 16,
            "auditor_public_key": account.auditor_public_key,
        })
        .to_string();
        unsafe {
            assert_two_call_stable(
                kms_generate_withdraw_proof,
                account.handle,
                &withdraw_params,
            )
        };

        let ragequit_params = json!({
            "recipient_address": felt_hex_fixed(&Felt::from(999u64)),
            "nonce": felt_hex_fixed(&Felt::from(5u64)),
            "chain_id": felt_hex_fixed(&account.chain_id),
            "tongo_address": felt_hex_fixed(&account.contract_address),
            "sender_address": felt_hex_fixed(&account.contract_address),
            "current_cipher": &account.current_cipher,
            "auditor_public_key": account.auditor_public_key,
        })
        .to_string();
        unsafe {
            assert_two_call_stable(
                kms_generate_ragequit_proof,
                account.handle,
                &ragequit_params,
            )
        };
    }
}
