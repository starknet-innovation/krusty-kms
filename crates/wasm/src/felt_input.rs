//! Shared parsing rule for JavaScript felt inputs.

use starknet_types_core::felt::Felt;

// Stark field modulus minus one. Check the integer text before Felt parsing:
// its hex and decimal constructors can reduce the modulus to zero.
const FELT_MAX_DECIMAL: &str =
    "3618502788666131213697322783095070105623107215331596699973092056135872020480";
const FELT_MAX_HEX: &str = "800000000000011000000000000000000000000000000000000000000000000";

/// A `0x`/`0X` prefix means hexadecimal; unprefixed ASCII digits mean decimal.
/// Unprefixed hexadecimal text is refused so it cannot silently change value.
pub(crate) fn parse_felt(value: &str) -> Result<Felt, String> {
    if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("hex felt must contain only hex digits".to_string());
        }
        let canonical = digits.trim_start_matches('0');
        let canonical = if canonical.is_empty() { "0" } else { canonical };
        if canonical.len() > FELT_MAX_HEX.len()
            || (canonical.len() == FELT_MAX_HEX.len()
                && canonical
                    .bytes()
                    .map(|byte| byte.to_ascii_lowercase())
                    .cmp(FELT_MAX_HEX.bytes())
                    .is_gt())
        {
            return Err("hex felt exceeds the field modulus".to_string());
        }
        return Felt::from_hex(digits).map_err(|e| format!("invalid hex felt: {e}"));
    }

    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("expected decimal digits or a 0x-prefixed hex felt".to_string());
    }
    let digits = value.trim_start_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    if digits.len() > FELT_MAX_DECIMAL.len()
        || (digits.len() == FELT_MAX_DECIMAL.len() && digits > FELT_MAX_DECIMAL)
    {
        return Err("decimal felt exceeds the field modulus".to_string());
    }
    Felt::from_dec_str(digits).map_err(|e| format!("invalid decimal felt: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn unprefixed_digits_are_decimal() {
        assert_eq!(parse_felt("1000").unwrap(), Felt::from(1000u64));
        assert_eq!(
            parse_felt("1000000000000000000").unwrap(),
            Felt::from(10u64.pow(18))
        );
        assert_eq!(parse_felt("0x1000").unwrap(), Felt::from(4096u64));
        assert_eq!(parse_felt("0X1000").unwrap(), Felt::from(4096u64));
    }

    #[wasm_bindgen_test]
    fn ambiguous_or_malformed_inputs_are_rejected() {
        for value in [
            "", "0x", "0X", "abcd", "0xzz", " 1000", "1000 ", "+10", "-1",
        ] {
            assert!(parse_felt(value).is_err(), "{value:?}");
        }
    }

    #[wasm_bindgen_test]
    fn decimal_out_of_range_is_rejected_without_reduction() {
        assert_eq!(FELT_MAX_DECIMAL, Felt::MAX.to_string());
        assert!(parse_felt(&Felt::MAX.to_string()).is_ok());
        assert!(parse_felt(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        )
        .is_err());
    }

    #[wasm_bindgen_test]
    fn hex_out_of_range_is_rejected_without_reduction() {
        assert_eq!(FELT_MAX_HEX, format!("{:x}", Felt::MAX));
        assert!(parse_felt(&format!("{:#x}", Felt::MAX)).is_ok());
        assert!(
            parse_felt("0x800000000000011000000000000000000000000000000000000000000000001")
                .is_err()
        );
    }
}
