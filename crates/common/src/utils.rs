//! Utility functions for Tongo protocol.

use crate::{Amount, KmsError, Result};
use starknet_types_core::felt::Felt;

const STRK_DECIMALS: u8 = 18;

/// Parse a hex string to Felt, handling various formats.
pub fn parse_hex_to_felt(hex: &str) -> Result<Felt> {
    Felt::from_hex(hex).map_err(|e| KmsError::DeserializationError(e.to_string()))
}

/// Convert Felt to hex string with 0x prefix.
pub fn felt_to_hex(felt: &Felt) -> String {
    format!("{:#x}", felt)
}

/// Left-pad a hex string to the specified length.
pub fn left_pad_hex(hex: &str, length: usize) -> String {
    let hex_clean = hex.strip_prefix("0x").unwrap_or(hex);
    if hex_clean.len() >= length {
        hex_clean.to_string()
    } else {
        format!("{:0>width$}", hex_clean, width = length)
    }
}

/// Serialize public key as concatenated x,y coordinates (128 hex chars).
pub fn serialize_public_key_hex(x: &Felt, y: &Felt) -> String {
    let x_hex = left_pad_hex(format!("{:#x}", x).trim_start_matches("0x"), 64);
    let y_hex = left_pad_hex(format!("{:#x}", y).trim_start_matches("0x"), 64);
    format!("0x{}{}", x_hex, y_hex)
}

/// Parse public key from concatenated hex format.
///
/// Accepted formats (all yielding 128 hex-digit x||y payload):
/// - `0x` + 128 hex chars
/// - `04` + 128 hex chars  (SEC1 uncompressed, no 0x)
/// - `0x04` + 128 hex chars
/// - bare 128 hex chars
pub fn parse_public_key_hex(hex: &str) -> Result<(Felt, Felt)> {
    let without_0x = hex.strip_prefix("0x");

    // Only strip a leading "04" when it is the SEC1 uncompressed-point tag,
    // i.e. when the total remaining length is 130 (2 + 128).
    let cleaned = match without_0x {
        Some(s) if s.starts_with("04") && s.len() == 130 => &s[2..],
        Some(s) => s,
        None if hex.starts_with("04") && hex.len() == 130 => &hex[2..],
        None => hex,
    };

    parse_public_key_digits(cleaned)
}

/// Parse a public key given as `0x` (or `0X`) followed by exactly 128 hex
/// digits.
///
/// This is the format the WASM and C ABI boundaries accept for recipient and
/// auditor keys: unlike [`parse_public_key_hex`], the prefix is required and
/// the SEC1 `04` tag is not stripped.
pub fn parse_prefixed_public_key_hex(hex: &str) -> Result<(Felt, Felt)> {
    let digits = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .ok_or_else(|| KmsError::InvalidPublicKey("Public key must start with 0x".to_string()))?;
    parse_public_key_digits(digits)
}

/// Split 128 hex digits into the x and y coordinates.
///
/// Both checks run before the split. `len()` counts bytes, so 128 bytes that
/// hold a multi-byte character would otherwise pass the length check and
/// panic on the byte-offset slice, which on wasm32 traps the whole module.
fn parse_public_key_digits(digits: &str) -> Result<(Felt, Felt)> {
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(KmsError::InvalidPublicKey(
            "Public key must contain only hex digits".to_string(),
        ));
    }
    if digits.len() != 128 {
        return Err(KmsError::InvalidPublicKey(format!(
            "Expected 128 hex chars, got {}",
            digits.len()
        )));
    }

    let (x_hex, y_hex) = digits.split_at(64);
    let x = Felt::from_hex(&format!("0x{x_hex}"))
        .map_err(|e| KmsError::InvalidPublicKey(e.to_string()))?;
    let y = Felt::from_hex(&format!("0x{y_hex}"))
        .map_err(|e| KmsError::InvalidPublicKey(e.to_string()))?;

    Ok((x, y))
}

/// Convert STRK (as string) to FRI (base units).
pub fn strk_to_fri(strk: &str) -> Result<u128> {
    let strk_clean = strk.trim().trim_end_matches("STRK").trim();
    if strk_clean.starts_with('-') {
        return Err(KmsError::InvalidAmount(
            "Amount cannot be negative".to_string(),
        ));
    }

    Amount::from_human(strk_clean, STRK_DECIMALS).map(|amount| amount.raw())
}

/// Convert FRI (base units) to a precision-safe STRK amount.
#[must_use]
pub fn fri_to_strk(fri: u128) -> Amount {
    Amount::from_raw(fri, STRK_DECIMALS)
}

/// Convert Tongo units to STRK using an exact rate.
///
/// # Errors
/// Returns `KmsError::InvalidAmount` if the rate is zero or the conversion overflows.
pub fn tongo_to_strk(tongo_amount: u128, rate: u128) -> Result<Amount> {
    let fri = tongo_to_base_units(tongo_amount, rate)?;
    Ok(fri_to_strk(fri))
}

/// Convert raw base units to Tongo units using rate.
///
/// # Errors
/// Returns `KmsError::InvalidAmount` if the rate is zero.
pub fn base_units_to_tongo(amount: u128, rate: u128) -> Result<u128> {
    validate_rate(rate)?;
    Ok(amount.div_ceil(rate))
}

/// Convert Tongo units to raw base units using an exact rate.
///
/// # Errors
/// Returns `KmsError::InvalidAmount` if the rate is zero or the conversion overflows.
pub fn tongo_to_base_units(tongo_amount: u128, rate: u128) -> Result<u128> {
    validate_rate(rate)?;
    tongo_amount
        .checked_mul(rate)
        .ok_or_else(|| KmsError::InvalidAmount("Amount overflow".to_string()))
}

/// Convert STRK to Tongo units using rate.
///
/// # Errors
/// Returns `KmsError::InvalidAmount` if the STRK amount is invalid or the rate is zero.
pub fn strk_to_tongo(strk: &str, rate: u128) -> Result<u128> {
    let fri = strk_to_fri(strk)?;
    base_units_to_tongo(fri, rate)
}

/// Format Tongo balance as STRK with 2 decimal places.
///
/// # Errors
/// Returns `KmsError::InvalidAmount` if the rate is zero or the conversion overflows.
pub fn format_tongo_balance(tongo_amount: u128, rate: u128) -> Result<String> {
    let strk = tongo_to_strk(tongo_amount, rate)?;
    Ok(format!("{} STRK", format_amount_with_scale(&strk, 2)?))
}

fn validate_rate(rate: u128) -> Result<()> {
    if rate == 0 {
        return Err(KmsError::InvalidAmount(
            "Rate must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn format_amount_with_scale(amount: &Amount, scale: u8) -> Result<String> {
    let decimals = amount.decimals();

    if scale == 0 {
        let divisor = ten_pow(decimals)?;
        let rounded = round_div(amount.raw(), divisor)?;
        return Ok(rounded.to_string());
    }

    if decimals > scale {
        let divisor = ten_pow(decimals - scale)?;
        let rounded = round_div(amount.raw(), divisor)?;
        return format_scaled_integer(rounded, scale);
    }

    let multiplier = ten_pow(scale - decimals)?;
    let scaled = amount
        .raw()
        .checked_mul(multiplier)
        .ok_or_else(|| KmsError::InvalidAmount("Amount overflow".to_string()))?;
    format_scaled_integer(scaled, scale)
}

fn round_div(value: u128, divisor: u128) -> Result<u128> {
    let half = divisor / 2;
    let adjusted = value
        .checked_add(half)
        .ok_or_else(|| KmsError::InvalidAmount("Amount overflow".to_string()))?;
    Ok(adjusted / divisor)
}

fn format_scaled_integer(value: u128, scale: u8) -> Result<String> {
    let factor = ten_pow(scale)?;
    let integer = value / factor;
    let fraction = value % factor;
    Ok(format!(
        "{}.{:0width$}",
        integer,
        fraction,
        width = usize::from(scale)
    ))
}

fn ten_pow(exp: u8) -> Result<u128> {
    10u128
        .checked_pow(u32::from(exp))
        .ok_or_else(|| KmsError::InvalidAmount("Amount overflow".to_string()))
}

#[cfg(test)]
mod tests;
