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

    if cleaned.len() != 128 {
        return Err(KmsError::InvalidPublicKey(format!(
            "Expected 128 hex chars, got {}",
            cleaned.len()
        )));
    }

    let x_hex = &cleaned[..64];
    let y_hex = &cleaned[64..];

    let x = Felt::from_hex(&format!("0x{}", x_hex))
        .map_err(|e| KmsError::InvalidPublicKey(e.to_string()))?;
    let y = Felt::from_hex(&format!("0x{}", y_hex))
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
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_to_felt() {
        let felt = parse_hex_to_felt("0x123").unwrap();
        assert_eq!(felt, Felt::from(0x123u64));

        let felt2 = parse_hex_to_felt("0xabcdef").unwrap();
        assert_eq!(felt2, Felt::from(0xabcdefu64));

        // Invalid hex should error
        assert!(parse_hex_to_felt("not_hex").is_err());
    }

    #[test]
    fn test_felt_to_hex() {
        let felt = Felt::from(0x123u64);
        let hex = felt_to_hex(&felt);
        assert_eq!(hex, "0x123");

        let felt_zero = Felt::ZERO;
        let hex_zero = felt_to_hex(&felt_zero);
        assert_eq!(hex_zero, "0x0");
    }

    #[test]
    fn test_left_pad_hex() {
        assert_eq!(left_pad_hex("abc", 6), "000abc");
        assert_eq!(left_pad_hex("0xabc", 6), "000abc");
        assert_eq!(left_pad_hex("abcdef", 6), "abcdef");
        assert_eq!(left_pad_hex("abcdefgh", 6), "abcdefgh");
    }

    #[test]
    fn test_serialize_public_key_hex() {
        let x = Felt::from(0x1u64);
        let y = Felt::from(0x2u64);
        let hex = serialize_public_key_hex(&x, &y);
        // Should be 0x + 64 chars for x + 64 chars for y
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + 128); // "0x" + 128 hex chars
    }

    #[test]
    fn test_parse_public_key_hex() {
        // Create a valid 128-char hex string
        let x_hex = "0".repeat(63) + "1"; // 64 chars representing x=1
        let y_hex = "0".repeat(63) + "2"; // 64 chars representing y=2
        let full_hex = format!("0x{}{}", x_hex, y_hex);

        let (x, y) = parse_public_key_hex(&full_hex).unwrap();
        assert_eq!(x, Felt::from(1u64));
        assert_eq!(y, Felt::from(2u64));

        // Test with "04" prefix (uncompressed point format)
        let with_prefix = format!("04{}{}", x_hex, y_hex);
        let (x2, y2) = parse_public_key_hex(&with_prefix).unwrap();
        assert_eq!(x2, Felt::from(1u64));
        assert_eq!(y2, Felt::from(2u64));
    }

    #[test]
    fn test_parse_public_key_hex_x_starts_with_04() {
        // Regression: x-coordinate legitimately starts with "04".
        // The old code incorrectly stripped this as a SEC1 prefix.
        let x_hex = "04".to_string() + &"0".repeat(62); // 64 chars, starts with 04
        let y_hex = "0".repeat(63) + "2";
        let full_hex = format!("0x{}{}", x_hex, y_hex);

        let (x, y) = parse_public_key_hex(&full_hex).unwrap();
        assert_eq!(
            x,
            Felt::from_hex(&format!("0x{}", x_hex)).unwrap(),
            "x-coordinate starting with 04 must not be stripped"
        );
        assert_eq!(y, Felt::from(2u64));
    }

    #[test]
    fn test_parse_public_key_hex_0x04_prefix() {
        // SEC1 uncompressed with 0x prefix: 0x04 + 128 hex chars
        let x_hex = "0".repeat(63) + "1";
        let y_hex = "0".repeat(63) + "2";
        let full_hex = format!("0x04{}{}", x_hex, y_hex);

        let (x, y) = parse_public_key_hex(&full_hex).unwrap();
        assert_eq!(x, Felt::from(1u64));
        assert_eq!(y, Felt::from(2u64));
    }

    #[test]
    fn test_parse_public_key_hex_bare() {
        // Bare 128 hex chars, no prefix
        let x_hex = "0".repeat(63) + "1";
        let y_hex = "0".repeat(63) + "2";
        let full_hex = format!("{}{}", x_hex, y_hex);

        let (x, y) = parse_public_key_hex(&full_hex).unwrap();
        assert_eq!(x, Felt::from(1u64));
        assert_eq!(y, Felt::from(2u64));
    }

    #[test]
    fn test_parse_public_key_hex_bare_x_starts_with_04() {
        // Bare 128 hex chars, no prefix, with x-coordinate starting with "04"
        let x_hex = "04".to_string() + &"0".repeat(62); // 64 chars total, starts with "04"
        let y_hex = "0".repeat(63) + "2"; // 64 chars total
        let full_hex = format!("{}{}", x_hex, y_hex);

        let (x, y) = parse_public_key_hex(&full_hex).unwrap();
        assert_eq!(x, Felt::from_hex(&x_hex).unwrap());
        assert_eq!(y, Felt::from(2u64));
    }

    #[test]
    fn test_parse_public_key_hex_invalid_length() {
        // Too short
        let result = parse_public_key_hex("0x123");
        assert!(result.is_err());
        if let Err(KmsError::InvalidPublicKey(msg)) = result {
            assert!(msg.contains("Expected 128 hex chars"));
        }
    }

    #[test]
    fn test_strk_conversion() {
        assert_eq!(strk_to_fri("1.5").unwrap(), 1_500_000_000_000_000_000);
        assert_eq!(strk_to_fri("1.5 STRK").unwrap(), 1_500_000_000_000_000_000);
        assert_eq!(fri_to_strk(1_500_000_000_000_000_000).to_human(), "1.5");
    }

    #[test]
    fn test_strk_to_fri_negative() {
        let result = strk_to_fri("-1.0");
        assert!(result.is_err());
        if let Err(KmsError::InvalidAmount(msg)) = result {
            assert!(msg.contains("negative"));
        }
    }

    #[test]
    fn test_strk_to_fri_invalid() {
        let result = strk_to_fri("not_a_number");
        assert!(result.is_err());
    }

    #[test]
    fn test_tongo_conversion() {
        let rate = 1_000_000_000_000_000_000; // 1e18
        assert_eq!(tongo_to_strk(100, rate).unwrap().to_human(), "100.0");
        assert_eq!(strk_to_tongo("100 STRK", rate).unwrap(), 100);
    }

    #[test]
    fn test_format_tongo_balance() {
        let rate = 1_000_000_000_000_000_000u128; // 1e18
        let formatted = format_tongo_balance(100, rate).unwrap();
        assert_eq!(formatted, "100.00 STRK");

        let formatted_small = format_tongo_balance(1, rate).unwrap();
        assert_eq!(formatted_small, "1.00 STRK");
    }

    #[test]
    fn test_strk_to_tongo_zero_rate() {
        let result = strk_to_tongo("1 STRK", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_tongo_to_strk_zero_rate() {
        let result = tongo_to_strk(1, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_tongo_balance_rounds_exactly() {
        let rate = 333_333_333_333_333_333u128;
        let formatted = format_tongo_balance(1, rate).unwrap();
        assert_eq!(formatted, "0.33 STRK");
    }
}
