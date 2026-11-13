//! Conversion from untrusted JavaScript proof parameters to SDK values.

use super::*;

/// Parse a decimal or prefixed hexadecimal felt.
pub(super) fn parse_felt(value: &str) -> WasmResult<Felt> {
    crate::felt_input::parse_felt(value).map_err(WasmError::SerializationError)
}

/// Parse a public key in the concatenated `0x{x_hex}{y_hex}` format (128 hex
/// digits after the prefix) to a `ProjectivePoint`.
///
/// The string comes from an untrusted counterparty (a Tongo recipient or
/// auditor key), and a panic here traps the module, so every check happens
/// in `parse_prefixed_public_key_hex` before anything is sliced.
pub(super) fn parse_public_key(hex: &str) -> WasmResult<ProjectivePoint> {
    let (x, y) = parse_prefixed_public_key_hex(hex.trim()).map_err(WasmError::from)?;
    ProjectivePoint::from_affine(x, y)
        .map_err(|e| WasmError::InvalidPublicKey(format!("Invalid point: {e:?}")))
}

/// Parse ciphertext coordinates to ElGamalCiphertext.
pub(super) fn parse_ciphertext(
    l_x: &str,
    l_y: &str,
    r_x: &str,
    r_y: &str,
) -> WasmResult<ElGamalCiphertext> {
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
pub(super) fn convert_fund_params(params: &WasmFundParams) -> WasmResult<FundParams> {
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
        sender_address: parse_felt(&params.sender_address)?,
        auditor_pub_key,
        current_balance,
    })
}

/// Convert WASM transfer params to SDK params.
pub(super) fn convert_transfer_params(params: &WasmTransferParams) -> WasmResult<TransferParams> {
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
        sender_address: parse_felt(&params.sender_address)?,
        current_balance,
        bit_size: params
            .bit_size
            .map(|b| b as usize)
            .unwrap_or(DEFAULT_BIT_SIZE),
        auditor_pub_key,
    })
}

/// Convert WASM withdraw params to SDK params.
pub(super) fn convert_withdraw_params(params: &WasmWithdrawParams) -> WasmResult<WithdrawParams> {
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
        sender_address: parse_felt(&params.sender_address)?,
        current_balance,
        bit_size: params
            .bit_size
            .map(|b| b as usize)
            .unwrap_or(DEFAULT_BIT_SIZE),
        auditor_key,
    })
}

/// Convert WASM ragequit params to SDK params.
pub(super) fn convert_ragequit_params(params: &WasmRagequitParams) -> WasmResult<RagequitParams> {
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
        sender_address: parse_felt(&params.sender_address)?,
        current_balance,
        auditor_key,
    })
}

/// Serialize audit data to JSON.
pub(super) fn serialize_audit(audit: &krusty_kms_sdk::operations::Audit) -> Result<String, String> {
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
        "hint_ciphertext": hex::encode(audit.hint_ciphertext),
        "hint_nonce": hex::encode(audit.hint_nonce),
        "proof": &audit.proof
    });

    serde_json::to_string(&json).map_err(|e| e.to_string())
}
