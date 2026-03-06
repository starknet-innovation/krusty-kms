//! Serde structs for JSON proof parameters and results.
//!
//! These mirror the WASM crate's param/result types but are consumed as
//! JSON strings over the FFI boundary rather than as JS objects.

use serde::{Deserialize, Serialize};

// ============================================================================
// Common ciphertext helper
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonCiphertext {
    pub l_x: String,
    pub l_y: String,
    pub r_x: String,
    pub r_y: String,
}

// ============================================================================
// Fund
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFundParams {
    pub amount: String,
    pub nonce: String,
    pub chain_id: String,
    pub tongo_address: String,
    pub sender_address: String,
    pub current_cipher: JsonCiphertext,
    #[serde(default)]
    pub fee_to_sender: Option<String>,
    pub auditor_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFundResult {
    pub y_x: String,
    pub y_y: String,
    pub proof_json: String,
    pub amount: String,
    pub audit_json: Option<String>,
}

// ============================================================================
// Transfer
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTransferParams {
    pub recipient_public_key: String,
    pub amount: String,
    pub nonce: String,
    pub chain_id: String,
    pub tongo_address: String,
    pub sender_address: String,
    pub current_cipher: JsonCiphertext,
    pub bit_size: Option<u8>,
    #[serde(default)]
    pub fee_to_sender: Option<String>,
    pub auditor_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTransferResult {
    pub transfer_l_x: String,
    pub transfer_l_y: String,
    pub transfer_r_x: String,
    pub transfer_r_y: String,
    pub self_l_x: String,
    pub self_l_y: String,
    pub self_r_x: String,
    pub self_r_y: String,
    pub new_balance_l_x: String,
    pub new_balance_l_y: String,
    pub new_balance_r_x: String,
    pub new_balance_r_y: String,
    pub aux_v_x: String,
    pub aux_v_y: String,
    pub aux_r_x: String,
    pub aux_r_y: String,
    pub aux2_v_x: String,
    pub aux2_v_y: String,
    pub aux2_r_x: String,
    pub aux2_r_y: String,
    pub proof_json: String,
    pub audit_balance_json: Option<String>,
    pub audit_transfer_json: Option<String>,
}

// ============================================================================
// Rollover
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRolloverParams {
    pub nonce: String,
    pub chain_id: String,
    pub tongo_address: String,
    pub sender_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRolloverResult {
    pub y_x: String,
    pub y_y: String,
    pub proof_json: String,
    pub pending_amount: String,
}

// ============================================================================
// Withdraw
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWithdrawParams {
    pub recipient_address: String,
    pub amount: String,
    pub nonce: String,
    pub chain_id: String,
    pub tongo_address: String,
    pub sender_address: String,
    pub current_cipher: JsonCiphertext,
    pub bit_size: Option<u8>,
    #[serde(default)]
    pub fee_to_sender: Option<String>,
    pub auditor_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWithdrawResult {
    pub y_x: String,
    pub y_y: String,
    pub a_x_x: String,
    pub a_x_y: String,
    pub a_r_x: String,
    pub a_r_y: String,
    pub a_x2: String,
    pub a_y2: String,
    pub a_v_x: String,
    pub a_v_y: String,
    pub sx: String,
    pub sb: String,
    pub sr: String,
    pub v_aux_x: String,
    pub v_aux_y: String,
    pub r_aux_x: String,
    pub r_aux_y: String,
    pub range_json: String,
    pub amount: String,
    pub recipient: String,
    pub audit_json: Option<String>,
}

// ============================================================================
// Ragequit
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRagequitParams {
    pub recipient_address: String,
    pub nonce: String,
    pub chain_id: String,
    pub tongo_address: String,
    pub sender_address: String,
    pub current_cipher: JsonCiphertext,
    #[serde(default)]
    pub fee_to_sender: Option<String>,
    pub auditor_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRagequitResult {
    pub y_x: String,
    pub y_y: String,
    pub a_x_x: String,
    pub a_x_y: String,
    pub a_r_x: String,
    pub a_r_y: String,
    pub sx: String,
    pub amount: String,
    pub recipient: String,
    pub audit_json: Option<String>,
}
