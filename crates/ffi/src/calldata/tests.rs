use super::*;
use crate::account::{
    kms_account_create_from_private_key, kms_account_destroy, kms_account_update_state,
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
    sender_public_key: String,
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
    let owner_key_kms = felt_to_kms(&owner_private_key);

    let mut handle: KmsAccountHandle = 0;
    let rc = unsafe {
        kms_account_create_from_private_key(&owner_key_kms, &contract_addr_kms, &mut handle)
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
    let sender_public_key = point_hex_concat_xy(&owner_public_key);

    let auditor_public_key = point_hex_concat_xy(&StarkCurve::mul_generator(&Felt::from(777u64)));
    let recipient_public_key = point_hex_concat_xy(&StarkCurve::mul_generator(&Felt::from(99u64)));

    TestAccount {
        handle,
        contract_address,
        chain_id,
        current_cipher,
        auditor_public_key,
        sender_public_key,
        recipient_public_key,
    }
}

unsafe fn call_proof_endpoint(
    f: unsafe extern "C" fn(KmsAccountHandle, *const c_char, *mut c_char, usize, *mut usize) -> i32,
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

fn test_bytes<const N: usize>() -> [u8; N] {
    std::array::from_fn(|index| index as u8)
}

fn sample_audit_json() -> String {
    let (x, y) = generator_xy_hex();
    serde_json::json!({
        "audited_balance": {
            "l": {"x": x.clone(), "y": y.clone()},
            "r": {"x": x.clone(), "y": y.clone()}
        },
        "hint_ciphertext": hex::encode(test_bytes::<64>()),
        "hint_nonce": hex::encode(test_bytes::<24>()),
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
        "hint_ciphertext_hex": hex::encode(test_bytes::<64>()),
        "hint_nonce_hex": hex::encode(test_bytes::<24>())
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

fn transfer_proof_result_json(account: &TestAccount) -> String {
    let proof_params = json!({
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
    unsafe { call_proof_endpoint(kms_generate_transfer_proof, account.handle, &proof_params) }
}

/// Distinct from `test_bytes` so the two hints cannot be confused.
fn leftover_bytes<const N: usize>() -> [u8; N] {
    std::array::from_fn(|index| 0xA0 + index as u8)
}

fn ae_balance_hex<const C: usize, const N: usize>(ct: &[u8; C], nonce: &[u8; N]) -> Vec<String> {
    felts_to_hex_vec(&serialization::serialize_ae_balance(ct, nonce).unwrap())
}

/// Proof-result fields that land verbatim (as felts) in the calldata:
/// `transferBalance` + `transferBalanceSelf` at 4..12, the two auxiliary
/// ciphers at 24..32.
const TRANSFER_CIPHER_FIELDS: [&str; 8] = [
    "transfer_l_x",
    "transfer_l_y",
    "transfer_r_x",
    "transfer_r_y",
    "self_l_x",
    "self_l_y",
    "self_r_x",
    "self_r_y",
];
const AUX_CIPHER_FIELDS: [&str; 8] = [
    "aux_v_x", "aux_v_y", "aux_r_x", "aux_r_y", "aux2_v_x", "aux2_v_y", "aux2_r_x", "aux2_r_y",
];

/// Regression test for audit finding H-2 (2026-11-04): the FFI transfer
/// calldata must follow the Cairo `Transfer` struct exactly as
/// `krusty_kms_client::build_transfer_call` emits it. The earlier encoder
/// started at `transferBalance` and carried one hint, so every C ABI transfer
/// reverted on chain.
#[test]
fn transfer_calldata_matches_contract_layout() {
    let account = create_test_account(1000);
    let proof_result_json = transfer_proof_result_json(&account);
    let proof_result: serde_json::Value = serde_json::from_str(&proof_result_json).unwrap();
    assert!(proof_result["audit_balance_json"].is_string());
    assert!(proof_result["audit_transfer_json"].is_string());

    let encode_params = json!({
        "tongo_address": felt_hex_fixed(&account.contract_address),
        "sender_public_key": account.sender_public_key,
        "recipient_public_key": account.recipient_public_key,
        "proof_result_json": proof_result_json,
        "hint_ciphertext_hex": hex::encode(test_bytes::<64>()),
        "hint_nonce_hex": hex::encode(test_bytes::<24>()),
        "hint_leftover_ciphertext_hex": hex::encode(leftover_bytes::<64>()),
        "hint_leftover_nonce_hex": hex::encode(leftover_bytes::<24>()),
    })
    .to_string();
    let encoded_json = unsafe { call_encode_endpoint(kms_encode_transfer_calls, &encode_params) };
    let encoded: EncodedCalls = serde_json::from_str(&encoded_json).unwrap();
    assert_eq!(encoded.calls.len(), 1);
    let calldata = &encoded.calls[0].calldata;
    let norm = |s: &str| felt_hex_fixed(&Felt::from_hex(s).unwrap());

    // 1-2. from, to: the sender's and recipient's Tongo public keys.
    let (from_x, from_y) = point_hex_xy(&StarkCurve::mul_generator(&Felt::from(42u64)));
    let (to_x, to_y) = point_hex_xy(&StarkCurve::mul_generator(&Felt::from(99u64)));
    let keys: Vec<String> = calldata[..4].iter().map(|s| norm(s)).collect();
    assert_eq!(keys, [from_x, from_y, to_x, to_y]);

    // 3-4 and 7-8. Cipher points, in proof-result order.
    for (offset, fields) in [(4, TRANSFER_CIPHER_FIELDS), (24, AUX_CIPHER_FIELDS)] {
        for (i, field) in fields.iter().enumerate() {
            let expected = norm(proof_result[*field].as_str().unwrap());
            assert_eq!(norm(&calldata[offset + i]), expected, "{field}");
        }
    }

    // 5-6. hintTransfer, then hintLeftover, as AEBalance (6 felts each).
    let hint_transfer = ae_balance_hex(&test_bytes::<64>(), &test_bytes::<24>());
    let hint_leftover = ae_balance_hex(&leftover_bytes::<64>(), &leftover_bytes::<24>());
    assert_ne!(hint_transfer, hint_leftover);
    assert_eq!(&calldata[12..18], hint_transfer.as_slice());
    assert_eq!(&calldata[18..24], hint_leftover.as_slice());

    // 9. proof, then 10-11. two `Option<Audit>` with the `Some` tag.
    let proof: ProofOfTransfer =
        serde_json::from_str(proof_result["proof_json"].as_str().unwrap()).unwrap();
    let proof_felts = serialization::serialize_proof_of_transfer(&proof).unwrap();
    let base_len = 32 + proof_felts.len();
    assert_eq!(
        &calldata[32..base_len],
        felts_to_hex_vec(&proof_felts).as_slice()
    );
    let audit_some_len = 1 + 4 + 6 + 11;
    assert_eq!(calldata[base_len], "0x0");
    assert_eq!(calldata[base_len + audit_some_len], "0x0");
    assert_eq!(calldata.len(), base_len + 2 * audit_some_len);
}

#[test]
fn transfer_calldata_rejects_pre_fix_parameter_shape() {
    let account = create_test_account(1000);
    let proof_result_json = transfer_proof_result_json(&account);

    // The shape accepted before the H-2 fix: no keys and a single hint.
    let legacy_params = json!({
        "tongo_address": felt_hex_fixed(&account.contract_address),
        "proof_result_json": proof_result_json,
        "hint_ciphertext_hex": hex::encode(test_bytes::<64>()),
        "hint_nonce_hex": hex::encode(test_bytes::<24>()),
    })
    .to_string();
    let params_c = CString::new(legacy_params).unwrap();
    let mut needed = 0usize;
    let rc = unsafe {
        kms_encode_transfer_calls(params_c.as_ptr(), std::ptr::null_mut(), 0, &mut needed)
    };
    assert_eq!(rc, crate::error::KMS_ERR_JSON);
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
        "sender_address": felt_hex_fixed(&account.contract_address),
        "current_cipher": &account.current_cipher,
        "bit_size": 16,
        "auditor_public_key": account.auditor_public_key,
    })
    .to_string();
    let proof_result_json =
        unsafe { call_proof_endpoint(kms_generate_withdraw_proof, account.handle, &proof_params) };
    let proof_result: serde_json::Value = serde_json::from_str(&proof_result_json).unwrap();
    assert!(proof_result["audit_json"].is_string());

    let encode_params = json!({
        "tongo_address": felt_hex_fixed(&account.contract_address),
        "proof_result_json": proof_result_json,
        "hint_ciphertext_hex": hex::encode(test_bytes::<64>()),
        "hint_nonce_hex": hex::encode(test_bytes::<24>()),
    })
    .to_string();
    let encoded_json = unsafe { call_encode_endpoint(kms_encode_withdraw_calls, &encode_params) };
    let encoded: EncodedCalls = serde_json::from_str(&encoded_json).unwrap();

    assert_eq!(encoded.calls.len(), 1);
    let calldata = &encoded.calls[0].calldata;

    let range_json = proof_result["range_json"].as_str().unwrap();
    let range: Range = serde_json::from_str(range_json).unwrap();
    let range_len = krusty_kms_sdk::serialization::serialize_range(&range)
        .unwrap()
        .len();

    // y(2) + recipient(1) + amount(1) + hint(6) + aux_cipher(4) + commitments(8) + scalars(3) + range
    let base_len = 25 + range_len;
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
        "sender_address": felt_hex_fixed(&account.contract_address),
        "current_cipher": &account.current_cipher,
        "auditor_public_key": account.auditor_public_key,
    })
    .to_string();
    let proof_result_json =
        unsafe { call_proof_endpoint(kms_generate_ragequit_proof, account.handle, &proof_params) };
    let proof_result: serde_json::Value = serde_json::from_str(&proof_result_json).unwrap();
    assert!(proof_result["audit_json"].is_string());

    let encode_params = json!({
        "tongo_address": felt_hex_fixed(&account.contract_address),
        "proof_result_json": proof_result_json,
        "hint_ciphertext_hex": hex::encode(test_bytes::<64>()),
        "hint_nonce_hex": hex::encode(test_bytes::<24>()),
    })
    .to_string();
    let encoded_json = unsafe { call_encode_endpoint(kms_encode_ragequit_calls, &encode_params) };
    let encoded: EncodedCalls = serde_json::from_str(&encoded_json).unwrap();

    assert_eq!(encoded.calls.len(), 1);
    let calldata = &encoded.calls[0].calldata;

    let base_len = 15;
    let audit_some_len = 1 + 4 + 6 + 11;
    assert_eq!(calldata[base_len], "0x0");
    assert_eq!(calldata.len(), base_len + audit_some_len);
}
