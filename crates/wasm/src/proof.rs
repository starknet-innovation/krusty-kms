//! WASM bindings for TONGO proof generation.
//!
//! Provides JavaScript-accessible functions for generating zero-knowledge
//! proofs required for TONGO protocol operations.

use crate::account::WasmAccount;
use crate::error::{from_sdk_result, WasmError, WasmResult};
use krusty_kms_common::ElGamalCiphertext;
use serde::{Deserialize, Serialize};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;
use krusty_kms_sdk::operations::{
    fund, ragequit, rollover, transfer, withdraw, FundParams, RagequitParams, RolloverParams,
    TransferParams, WithdrawParams,
};
use wasm_bindgen::prelude::*;

/// Default bit size for range proofs (40 bits = ~1 trillion max).
const DEFAULT_BIT_SIZE: usize = 40;

// ============================================================================
// Fund Operation
// ============================================================================

/// Parameters for generating a fund proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmFundParams {
    /// Amount to deposit (string for large numbers)
    pub amount: String,
    /// Transaction nonce (hex)
    pub nonce: String,
    /// Chain ID (hex)
    pub chain_id: String,
    /// TONGO contract address (hex)
    pub tongo_address: String,
    /// Current balance ciphertext
    pub current_cipher_l_x: String,
    pub current_cipher_l_y: String,
    pub current_cipher_r_x: String,
    pub current_cipher_r_y: String,
    /// Optional auditor public key (hex, concatenated x||y)
    pub auditor_public_key: Option<String>,
}

#[wasm_bindgen]
impl WasmFundParams {
    #[wasm_bindgen(constructor)]
    pub fn new(
        amount: String,
        nonce: String,
        chain_id: String,
        tongo_address: String,
        current_cipher_l_x: String,
        current_cipher_l_y: String,
        current_cipher_r_x: String,
        current_cipher_r_y: String,
    ) -> Self {
        Self {
            amount,
            nonce,
            chain_id,
            tongo_address,
            current_cipher_l_x,
            current_cipher_l_y,
            current_cipher_r_x,
            current_cipher_r_y,
            auditor_public_key: None,
        }
    }

    #[wasm_bindgen(js_name = "withAuditor")]
    pub fn with_auditor(mut self, auditor_public_key: String) -> Self {
        self.auditor_public_key = Some(auditor_public_key);
        self
    }
}

/// Result of a fund proof generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmFundProofResult {
    /// Public key Y point (x coordinate)
    pub y_x: String,
    /// Public key Y point (y coordinate)
    pub y_y: String,
    /// PoE proof as JSON
    pub proof_json: String,
    /// Amount funded
    pub amount: String,
    /// Audit data as JSON (if auditor configured)
    pub audit_json: Option<String>,
}

/// Generate a fund (deposit) proof.
#[wasm_bindgen(js_name = "generateFundProof")]
pub fn generate_fund_proof(
    account: &WasmAccount,
    params: &WasmFundParams,
) -> Result<WasmFundProofResult, JsValue> {
    let sdk_params = convert_fund_params(params)?;
    let proof = from_sdk_result(fund(&account.inner, sdk_params)).map_err(JsValue::from)?;

    let y_affine = proof
        .y
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid Y point"))?;

    let proof_json = serde_json::to_string(&proof.proof)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))?;

    let audit_json = proof
        .audit
        .map(|a| serialize_audit(&a))
        .transpose()
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(WasmFundProofResult {
        y_x: format!("{:#x}", y_affine.x()),
        y_y: format!("{:#x}", y_affine.y()),
        proof_json,
        amount: proof.amount.to_string(),
        audit_json,
    })
}

// ============================================================================
// Transfer Operation
// ============================================================================

/// Parameters for generating a transfer proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmTransferParams {
    /// Recipient's public key (viewing key for dual-key wallets)
    pub recipient_public_key: String,
    /// Amount to transfer
    pub amount: String,
    /// Transaction nonce (hex)
    pub nonce: String,
    /// Chain ID (hex)
    pub chain_id: String,
    /// TONGO contract address (hex)
    pub tongo_address: String,
    /// Current balance ciphertext
    pub current_cipher_l_x: String,
    pub current_cipher_l_y: String,
    pub current_cipher_r_x: String,
    pub current_cipher_r_y: String,
    /// Bit size for range proof (default: 40)
    pub bit_size: Option<u8>,
    /// Optional auditor public key
    pub auditor_public_key: Option<String>,
}

#[wasm_bindgen]
impl WasmTransferParams {
    #[wasm_bindgen(constructor)]
    pub fn new(
        recipient_public_key: String,
        amount: String,
        nonce: String,
        chain_id: String,
        tongo_address: String,
        current_cipher_l_x: String,
        current_cipher_l_y: String,
        current_cipher_r_x: String,
        current_cipher_r_y: String,
    ) -> Self {
        Self {
            recipient_public_key,
            amount,
            nonce,
            chain_id,
            tongo_address,
            current_cipher_l_x,
            current_cipher_l_y,
            current_cipher_r_x,
            current_cipher_r_y,
            bit_size: None,
            auditor_public_key: None,
        }
    }

    #[wasm_bindgen(js_name = "withBitSize")]
    pub fn with_bit_size(mut self, bit_size: u8) -> Self {
        self.bit_size = Some(bit_size);
        self
    }

    #[wasm_bindgen(js_name = "withAuditor")]
    pub fn with_auditor(mut self, auditor_public_key: String) -> Self {
        self.auditor_public_key = Some(auditor_public_key);
        self
    }
}

/// Result of a transfer proof generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmTransferProofResult {
    /// Transfer cipher for recipient (L)
    pub transfer_l_x: String,
    pub transfer_l_y: String,
    /// Transfer cipher for recipient (R)
    pub transfer_r_x: String,
    pub transfer_r_y: String,
    /// Transfer cipher for self (L)
    pub self_l_x: String,
    pub self_l_y: String,
    /// Transfer cipher for self (R)
    pub self_r_x: String,
    pub self_r_y: String,
    /// New balance cipher (L)
    pub new_balance_l_x: String,
    pub new_balance_l_y: String,
    /// New balance cipher (R)
    pub new_balance_r_x: String,
    pub new_balance_r_y: String,
    /// Complete transfer proof as JSON
    pub proof_json: String,
    /// Audit for balance (if auditor configured)
    pub audit_balance_json: Option<String>,
    /// Audit for transfer (if auditor configured)
    pub audit_transfer_json: Option<String>,
}

/// Generate a transfer proof.
#[wasm_bindgen(js_name = "generateTransferProof")]
pub fn generate_transfer_proof(
    account: &WasmAccount,
    params: &WasmTransferParams,
) -> Result<WasmTransferProofResult, JsValue> {
    let sdk_params = convert_transfer_params(params)?;
    let proof = from_sdk_result(transfer(&account.inner, sdk_params)).map_err(JsValue::from)?;

    let transfer_l = proof
        .transfer_balance_l
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid transfer L point"))?;
    let transfer_r = proof
        .transfer_balance_r
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid transfer R point"))?;
    let self_l = proof
        .transfer_balance_self_l
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid self L point"))?;
    let self_r = proof
        .transfer_balance_self_r
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid self R point"))?;
    let new_l = proof
        .new_balance_cipher
        .l
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid new balance L point"))?;
    let new_r = proof
        .new_balance_cipher
        .r
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid new balance R point"))?;

    let proof_json = serde_json::to_string(&proof.proof)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))?;

    let audit_balance_json = proof
        .audit_balance
        .map(|a| serialize_audit(&a))
        .transpose()
        .map_err(|e| JsValue::from_str(&e))?;

    let audit_transfer_json = proof
        .audit_transfer
        .map(|a| serialize_audit(&a))
        .transpose()
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(WasmTransferProofResult {
        transfer_l_x: format!("{:#x}", transfer_l.x()),
        transfer_l_y: format!("{:#x}", transfer_l.y()),
        transfer_r_x: format!("{:#x}", transfer_r.x()),
        transfer_r_y: format!("{:#x}", transfer_r.y()),
        self_l_x: format!("{:#x}", self_l.x()),
        self_l_y: format!("{:#x}", self_l.y()),
        self_r_x: format!("{:#x}", self_r.x()),
        self_r_y: format!("{:#x}", self_r.y()),
        new_balance_l_x: format!("{:#x}", new_l.x()),
        new_balance_l_y: format!("{:#x}", new_l.y()),
        new_balance_r_x: format!("{:#x}", new_r.x()),
        new_balance_r_y: format!("{:#x}", new_r.y()),
        proof_json,
        audit_balance_json,
        audit_transfer_json,
    })
}

// ============================================================================
// Rollover Operation
// ============================================================================

/// Parameters for generating a rollover proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmRolloverParams {
    /// Transaction nonce (hex)
    pub nonce: String,
    /// Chain ID (hex)
    pub chain_id: String,
    /// TONGO contract address (hex)
    pub tongo_address: String,
}

#[wasm_bindgen]
impl WasmRolloverParams {
    #[wasm_bindgen(constructor)]
    pub fn new(nonce: String, chain_id: String, tongo_address: String) -> Self {
        Self {
            nonce,
            chain_id,
            tongo_address,
        }
    }
}

/// Result of a rollover proof generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmRolloverProofResult {
    /// Public key Y point
    pub y_x: String,
    pub y_y: String,
    /// PoE proof as JSON
    pub proof_json: String,
    /// Pending amount that was rolled over
    pub pending_amount: String,
}

/// Generate a rollover proof.
#[wasm_bindgen(js_name = "generateRolloverProof")]
pub fn generate_rollover_proof(
    account: &WasmAccount,
    params: &WasmRolloverParams,
) -> Result<WasmRolloverProofResult, JsValue> {
    let sdk_params = RolloverParams {
        nonce: parse_felt(&params.nonce)?,
        chain_id: parse_felt(&params.chain_id)?,
        tongo_address: parse_felt(&params.tongo_address)?,
    };

    let proof = from_sdk_result(rollover(&account.inner, sdk_params)).map_err(JsValue::from)?;

    let y_affine = proof
        .y
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid Y point"))?;

    let proof_json = serde_json::to_string(&proof.proof)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))?;

    Ok(WasmRolloverProofResult {
        y_x: format!("{:#x}", y_affine.x()),
        y_y: format!("{:#x}", y_affine.y()),
        proof_json,
        pending_amount: proof.pending_amount.to_string(),
    })
}

// ============================================================================
// Withdraw Operation
// ============================================================================

/// Parameters for generating a withdraw proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmWithdrawParams {
    /// Recipient address for withdrawn funds (hex)
    pub recipient_address: String,
    /// Amount to withdraw
    pub amount: String,
    /// Transaction nonce (hex)
    pub nonce: String,
    /// Chain ID (hex)
    pub chain_id: String,
    /// TONGO contract address (hex)
    pub tongo_address: String,
    /// Current balance ciphertext
    pub current_cipher_l_x: String,
    pub current_cipher_l_y: String,
    pub current_cipher_r_x: String,
    pub current_cipher_r_y: String,
    /// Bit size for range proof (default: 40)
    pub bit_size: Option<u8>,
    /// Optional auditor public key
    pub auditor_public_key: Option<String>,
}

#[wasm_bindgen]
impl WasmWithdrawParams {
    #[wasm_bindgen(constructor)]
    pub fn new(
        recipient_address: String,
        amount: String,
        nonce: String,
        chain_id: String,
        tongo_address: String,
        current_cipher_l_x: String,
        current_cipher_l_y: String,
        current_cipher_r_x: String,
        current_cipher_r_y: String,
    ) -> Self {
        Self {
            recipient_address,
            amount,
            nonce,
            chain_id,
            tongo_address,
            current_cipher_l_x,
            current_cipher_l_y,
            current_cipher_r_x,
            current_cipher_r_y,
            bit_size: None,
            auditor_public_key: None,
        }
    }

    #[wasm_bindgen(js_name = "withBitSize")]
    pub fn with_bit_size(mut self, bit_size: u8) -> Self {
        self.bit_size = Some(bit_size);
        self
    }

    #[wasm_bindgen(js_name = "withAuditor")]
    pub fn with_auditor(mut self, auditor_public_key: String) -> Self {
        self.auditor_public_key = Some(auditor_public_key);
        self
    }
}

/// Result of a withdraw proof generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmWithdrawProofResult {
    /// Public key Y point
    pub y_x: String,
    pub y_y: String,
    /// Commitments
    pub a_x_x: String,
    pub a_x_y: String,
    pub a_r_x: String,
    pub a_r_y: String,
    pub a_x2: String,
    pub a_y2: String,
    pub a_v_x: String,
    pub a_v_y: String,
    /// Scalar responses
    pub sx: String,
    pub sb: String,
    pub sr: String,
    /// Range proof auxiliary point
    pub r_aux_x: String,
    pub r_aux_y: String,
    /// Range proof as JSON
    pub range_json: String,
    /// Amount withdrawn
    pub amount: String,
    /// Recipient address
    pub recipient: String,
    /// Audit data as JSON (if auditor configured)
    pub audit_json: Option<String>,
}

/// Generate a withdraw proof.
#[wasm_bindgen(js_name = "generateWithdrawProof")]
pub fn generate_withdraw_proof(
    account: &WasmAccount,
    params: &WasmWithdrawParams,
) -> Result<WasmWithdrawProofResult, JsValue> {
    let sdk_params = convert_withdraw_params(params)?;
    let proof = from_sdk_result(withdraw(&account.inner, sdk_params)).map_err(JsValue::from)?;

    let y = proof
        .y
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid Y point"))?;
    let a_x = proof
        .a_x
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid A_x point"))?;
    let a_r = proof
        .a_r
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid A_r point"))?;
    let a = proof
        .a
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid A point"))?;
    let a_v = proof
        .a_v
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid A_v point"))?;
    let r_aux = proof
        .r_aux
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid R_aux point"))?;

    let range_json = serde_json::to_string(&proof.range)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))?;

    let audit_json = proof
        .audit
        .map(|a| serialize_audit(&a))
        .transpose()
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(WasmWithdrawProofResult {
        y_x: format!("{:#x}", y.x()),
        y_y: format!("{:#x}", y.y()),
        a_x_x: format!("{:#x}", a_x.x()),
        a_x_y: format!("{:#x}", a_x.y()),
        a_r_x: format!("{:#x}", a_r.x()),
        a_r_y: format!("{:#x}", a_r.y()),
        a_x2: format!("{:#x}", a.x()),
        a_y2: format!("{:#x}", a.y()),
        a_v_x: format!("{:#x}", a_v.x()),
        a_v_y: format!("{:#x}", a_v.y()),
        sx: format!("{:#x}", proof.sx),
        sb: format!("{:#x}", proof.sb),
        sr: format!("{:#x}", proof.sr),
        r_aux_x: format!("{:#x}", r_aux.x()),
        r_aux_y: format!("{:#x}", r_aux.y()),
        range_json,
        amount: proof.amount.to_string(),
        recipient: format!("{:#x}", proof.recipient),
        audit_json,
    })
}

// ============================================================================
// Ragequit Operation
// ============================================================================

/// Parameters for generating a ragequit proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmRagequitParams {
    /// Recipient address for withdrawn funds (hex)
    pub recipient_address: String,
    /// Transaction nonce (hex)
    pub nonce: String,
    /// Chain ID (hex)
    pub chain_id: String,
    /// TONGO contract address (hex)
    pub tongo_address: String,
    /// Current balance ciphertext
    pub current_cipher_l_x: String,
    pub current_cipher_l_y: String,
    pub current_cipher_r_x: String,
    pub current_cipher_r_y: String,
    /// Optional auditor public key
    pub auditor_public_key: Option<String>,
}

#[wasm_bindgen]
impl WasmRagequitParams {
    #[wasm_bindgen(constructor)]
    pub fn new(
        recipient_address: String,
        nonce: String,
        chain_id: String,
        tongo_address: String,
        current_cipher_l_x: String,
        current_cipher_l_y: String,
        current_cipher_r_x: String,
        current_cipher_r_y: String,
    ) -> Self {
        Self {
            recipient_address,
            nonce,
            chain_id,
            tongo_address,
            current_cipher_l_x,
            current_cipher_l_y,
            current_cipher_r_x,
            current_cipher_r_y,
            auditor_public_key: None,
        }
    }

    #[wasm_bindgen(js_name = "withAuditor")]
    pub fn with_auditor(mut self, auditor_public_key: String) -> Self {
        self.auditor_public_key = Some(auditor_public_key);
        self
    }
}

/// Result of a ragequit proof generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmRagequitProofResult {
    /// Public key Y point
    pub y_x: String,
    pub y_y: String,
    /// Commitment A_x = g^kx
    pub a_x_x: String,
    pub a_x_y: String,
    /// Commitment A_r = R0^kx
    pub a_r_x: String,
    pub a_r_y: String,
    /// Scalar response sx
    pub sx: String,
    /// Full balance amount
    pub amount: String,
    /// Recipient address
    pub recipient: String,
    /// Audit data as JSON (if auditor configured)
    pub audit_json: Option<String>,
}

/// Generate a ragequit (emergency exit) proof.
#[wasm_bindgen(js_name = "generateRagequitProof")]
pub fn generate_ragequit_proof(
    account: &WasmAccount,
    params: &WasmRagequitParams,
) -> Result<WasmRagequitProofResult, JsValue> {
    let sdk_params = convert_ragequit_params(params)?;
    let proof = from_sdk_result(ragequit(&account.inner, sdk_params)).map_err(JsValue::from)?;

    let y = proof
        .y
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid Y point"))?;
    let a_x = proof
        .a_x
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid A_x point"))?;
    let a_r = proof
        .a_r
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid A_r point"))?;

    let audit_json = proof
        .audit
        .map(|a| serialize_audit(&a))
        .transpose()
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(WasmRagequitProofResult {
        y_x: format!("{:#x}", y.x()),
        y_y: format!("{:#x}", y.y()),
        a_x_x: format!("{:#x}", a_x.x()),
        a_x_y: format!("{:#x}", a_x.y()),
        a_r_x: format!("{:#x}", a_r.x()),
        a_r_y: format!("{:#x}", a_r.y()),
        sx: format!("{:#x}", proof.sx),
        amount: proof.amount.to_string(),
        recipient: format!("{:#x}", proof.recipient),
        audit_json,
    })
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse a hex string to Felt.
fn parse_felt(hex: &str) -> WasmResult<Felt> {
    Felt::from_hex(hex).map_err(|e| WasmError::SerializationError(e.to_string()))
}

/// Parse a public key hex string to ProjectivePoint.
///
/// Accepts either:
/// - Concatenated format: "0x{x_hex}{y_hex}" (128 hex chars after 0x)
/// - Two-field JSON: {"x": "0x...", "y": "0x..."}
fn parse_public_key(hex: &str) -> WasmResult<ProjectivePoint> {
    let hex = hex.trim();

    // Try to parse as concatenated hex (0x + 64 chars for x + 64 chars for y)
    if hex.starts_with("0x") || hex.starts_with("0X") {
        let hex_data = &hex[2..];
        if hex_data.len() == 128 {
            // Split into x and y (64 hex chars each = 32 bytes each)
            let x_hex = format!("0x{}", &hex_data[..64]);
            let y_hex = format!("0x{}", &hex_data[64..]);

            let x = Felt::from_hex(&x_hex)
                .map_err(|e| WasmError::InvalidPublicKey(format!("Invalid X coordinate: {e}")))?;
            let y = Felt::from_hex(&y_hex)
                .map_err(|e| WasmError::InvalidPublicKey(format!("Invalid Y coordinate: {e}")))?;

            return ProjectivePoint::from_affine(x, y)
                .map_err(|e| WasmError::InvalidPublicKey(format!("Invalid point: {e:?}")));
        }
    }

    // Fallback: try parsing as a single felt (x coordinate only) - not supported
    Err(WasmError::InvalidPublicKey(
        "Public key must be in format 0x{x}{y} (128 hex chars after 0x)".to_string(),
    ))
}

/// Parse ciphertext coordinates to ElGamalCiphertext.
fn parse_ciphertext(l_x: &str, l_y: &str, r_x: &str, r_y: &str) -> WasmResult<ElGamalCiphertext> {
    let lx = parse_felt(l_x)?;
    let ly = parse_felt(l_y)?;
    let rx = parse_felt(r_x)?;
    let ry = parse_felt(r_y)?;

    let l = ProjectivePoint::from_affine(lx, ly)
        .map_err(|e| WasmError::CryptoError(format!("Invalid L point: {e:?}")))?;
    let r = ProjectivePoint::from_affine(rx, ry)
        .map_err(|e| WasmError::CryptoError(format!("Invalid R point: {e:?}")))?;

    Ok(ElGamalCiphertext { l, r })
}

/// Convert WASM fund params to SDK params.
fn convert_fund_params(params: &WasmFundParams) -> WasmResult<FundParams> {
    let amount: u128 = params
        .amount
        .parse()
        .map_err(|_| WasmError::InvalidAmount(params.amount.clone()))?;

    let current_balance = parse_ciphertext(
        &params.current_cipher_l_x,
        &params.current_cipher_l_y,
        &params.current_cipher_r_x,
        &params.current_cipher_r_y,
    )?;

    let auditor_pub_key = params
        .auditor_public_key
        .as_ref()
        .map(|pk| parse_public_key(pk))
        .transpose()?;

    Ok(FundParams {
        amount,
        nonce: parse_felt(&params.nonce)?,
        chain_id: parse_felt(&params.chain_id)?,
        tongo_address: parse_felt(&params.tongo_address)?,
        auditor_pub_key,
        current_balance,
    })
}

/// Convert WASM transfer params to SDK params.
fn convert_transfer_params(params: &WasmTransferParams) -> WasmResult<TransferParams> {
    let amount: u128 = params
        .amount
        .parse()
        .map_err(|_| WasmError::InvalidAmount(params.amount.clone()))?;

    let current_balance = parse_ciphertext(
        &params.current_cipher_l_x,
        &params.current_cipher_l_y,
        &params.current_cipher_r_x,
        &params.current_cipher_r_y,
    )?;

    let recipient_public_key = parse_public_key(&params.recipient_public_key)?;

    let auditor_pub_key = params
        .auditor_public_key
        .as_ref()
        .map(|pk| parse_public_key(pk))
        .transpose()?;

    Ok(TransferParams {
        recipient_public_key,
        amount,
        nonce: parse_felt(&params.nonce)?,
        chain_id: parse_felt(&params.chain_id)?,
        tongo_address: parse_felt(&params.tongo_address)?,
        current_balance,
        bit_size: params.bit_size.map(|b| b as usize).unwrap_or(DEFAULT_BIT_SIZE),
        auditor_pub_key,
    })
}

/// Convert WASM withdraw params to SDK params.
fn convert_withdraw_params(params: &WasmWithdrawParams) -> WasmResult<WithdrawParams> {
    let amount: u128 = params
        .amount
        .parse()
        .map_err(|_| WasmError::InvalidAmount(params.amount.clone()))?;

    let current_balance = parse_ciphertext(
        &params.current_cipher_l_x,
        &params.current_cipher_l_y,
        &params.current_cipher_r_x,
        &params.current_cipher_r_y,
    )?;

    let auditor_key = params
        .auditor_public_key
        .as_ref()
        .map(|pk| parse_public_key(pk))
        .transpose()?;

    Ok(WithdrawParams {
        recipient_address: parse_felt(&params.recipient_address)?,
        amount,
        nonce: parse_felt(&params.nonce)?,
        chain_id: parse_felt(&params.chain_id)?,
        tongo_address: parse_felt(&params.tongo_address)?,
        current_balance,
        bit_size: params.bit_size.map(|b| b as usize).unwrap_or(DEFAULT_BIT_SIZE),
        auditor_key,
    })
}

/// Convert WASM ragequit params to SDK params.
fn convert_ragequit_params(params: &WasmRagequitParams) -> WasmResult<RagequitParams> {
    let current_balance = parse_ciphertext(
        &params.current_cipher_l_x,
        &params.current_cipher_l_y,
        &params.current_cipher_r_x,
        &params.current_cipher_r_y,
    )?;

    let auditor_key = params
        .auditor_public_key
        .as_ref()
        .map(|pk| parse_public_key(pk))
        .transpose()?;

    Ok(RagequitParams {
        recipient_address: parse_felt(&params.recipient_address)?,
        nonce: parse_felt(&params.nonce)?,
        chain_id: parse_felt(&params.chain_id)?,
        tongo_address: parse_felt(&params.tongo_address)?,
        current_balance,
        auditor_key,
    })
}

/// Serialize audit data to JSON.
fn serialize_audit(audit: &krusty_kms_sdk::operations::Audit) -> Result<String, String> {
    use serde_json::json;

    let l_affine = audit
        .audited_balance
        .l
        .to_affine()
        .map_err(|_| "Invalid audit L point")?;
    let r_affine = audit
        .audited_balance
        .r
        .to_affine()
        .map_err(|_| "Invalid audit R point")?;

    let json = json!({
        "audited_balance": {
            "l": { "x": format!("{:#x}", l_affine.x()), "y": format!("{:#x}", l_affine.y()) },
            "r": { "x": format!("{:#x}", r_affine.x()), "y": format!("{:#x}", r_affine.y()) }
        },
        "hint_ciphertext": hex::encode(&audit.hint_ciphertext),
        "hint_nonce": hex::encode(&audit.hint_nonce),
        "proof": &audit.proof
    });

    serde_json::to_string(&json).map_err(|e| e.to_string())
}

