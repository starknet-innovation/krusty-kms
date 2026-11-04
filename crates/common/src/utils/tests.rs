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

/// 63 ASCII hex digits, U+00E9 (two bytes, straddling byte offset 64), 63
/// more: 128 bytes but 127 characters, so a byte-length check passes and a
/// byte-offset split at 64 lands inside the character.
fn straddling_digits() -> String {
    format!("{}\u{e9}{}", "a".repeat(63), "a".repeat(63))
}

#[test]
fn test_parse_public_key_hex_rejects_non_ascii_without_panicking() {
    let digits = straddling_digits();
    assert_eq!(digits.len(), 128);
    for input in [format!("0x{digits}"), digits.clone()] {
        let error = parse_public_key_hex(&input).unwrap_err();
        assert!(
            matches!(&error, KmsError::InvalidPublicKey(m) if m.contains("hex digits")),
            "{error}"
        );
    }
}

#[test]
fn test_parse_prefixed_public_key_hex() {
    let x_hex = "0".repeat(63) + "1";
    let y_hex = "0".repeat(63) + "2";
    let (x, y) = parse_prefixed_public_key_hex(&format!("0x{x_hex}{y_hex}")).unwrap();
    assert_eq!((x, y), (Felt::from(1u64), Felt::from(2u64)));
    let (x, y) = parse_prefixed_public_key_hex(&format!("0X{x_hex}{y_hex}")).unwrap();
    assert_eq!((x, y), (Felt::from(1u64), Felt::from(2u64)));

    // The prefix is required, the SEC1 tag is not stripped, and non-hex or
    // non-ASCII content is refused before any slicing.
    for (input, expected) in [
        (format!("{x_hex}{y_hex}"), "must start with 0x"),
        (
            format!("0x04{x_hex}{y_hex}"),
            "Expected 128 hex chars, got 130",
        ),
        (format!("0x{}", "g".repeat(128)), "hex digits"),
        (format!("0x{}", straddling_digits()), "hex digits"),
        ("0x".to_string(), "Expected 128 hex chars, got 0"),
    ] {
        let error = parse_prefixed_public_key_hex(&input).unwrap_err();
        assert!(
            matches!(&error, KmsError::InvalidPublicKey(m) if m.contains(expected)),
            "{input:?}: {error}"
        );
    }
}
