//! Exercise generated JavaScript accessors, including Copy and owned fields.
use krusty_kms_wasm::{
    types::WasmDecryptedPoint, WasmAccountState, WasmTransferParams, WasmWithdrawParams,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen(inline_js = r#"
function check(value, expected, message) {
    if (value !== expected) throw new Error(message);
}
export function checkAccount(state) {
    check(state.nonce, 7n, 'nonce getter');
    state.nonce = 9n;
    check(state.nonce, 9n, 'nonce setter');
    check(state.balance, '10', 'string getter');
    check(state.balance, '10', 'repeat string getter');
    state.balance = '20';
    check(state.balance, '20', 'string setter');
}
export function checkPoint(point) {
    check(point.is_identity, true, 'bool getter');
    point.is_identity = false;
    check(point.is_identity, false, 'bool setter');
    check(point.x, '0x0', 'point string getter');
}
export function checkParams(params) {
    check(params.bit_size, undefined, 'absent optional getter');
    params.bit_size = 40;
    check(params.bit_size, 40, 'optional setter and getter');
    params.bit_size = undefined;
    check(params.bit_size, undefined, 'clear optional setter');
    check(params.amount, '1', 'params string getter');
    check(params.amount, '1', 'repeat params string getter');
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = checkAccount)]
    fn check_account(state: WasmAccountState);
    #[wasm_bindgen(js_name = checkPoint)]
    fn check_point(point: WasmDecryptedPoint);
    #[wasm_bindgen(js_name = checkParams)]
    fn check_transfer(params: WasmTransferParams);
    #[wasm_bindgen(js_name = checkParams)]
    fn check_withdraw(params: WasmWithdrawParams);
}

#[wasm_bindgen_test]
fn generated_scalar_and_owned_accessors() {
    check_account(WasmAccountState {
        balance: "10".into(),
        pending_balance: "0".into(),
        nonce: 7,
    });
    check_point(WasmDecryptedPoint {
        is_identity: true,
        x: Some("0x0".into()),
        y: Some("0x0".into()),
    });
    let transfer: WasmTransferParams = serde_json::from_value(serde_json::json!({
        "recipient_public_key": "0x1", "amount": "1", "nonce": "0x1", "chain_id": "0x1",
        "tongo_address": "0x1", "sender_address": "0x1", "current_cipher_l_x": "0x1",
        "current_cipher_l_y": "0x1", "current_cipher_r_x": "0x1", "current_cipher_r_y": "0x1"
    }))
    .unwrap();
    check_transfer(transfer);
    let withdraw: WasmWithdrawParams = serde_json::from_value(serde_json::json!({
        "recipient_address": "0x1", "amount": "1", "nonce": "0x1", "chain_id": "0x1",
        "tongo_address": "0x1", "sender_address": "0x1", "current_cipher_l_x": "0x1",
        "current_cipher_l_y": "0x1", "current_cipher_r_x": "0x1", "current_cipher_r_y": "0x1"
    }))
    .unwrap();
    check_withdraw(withdraw);
}
