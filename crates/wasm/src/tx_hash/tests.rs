use super::*;

#[test]
fn test_parse_felt_valid() {
    assert!(parse_felt("0x1").is_ok());
    assert!(parse_felt("0xdeadbeef").is_ok());
    assert!(parse_felt("0x0").is_ok());
}

#[test]
fn test_parse_felts() {
    let inputs = vec!["0x1".to_string(), "0x2".to_string(), "0x3".to_string()];
    let result = parse_felts(&inputs);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 3);
}

#[test]
fn test_da_mode_from_u8() {
    assert!(da_mode_from_u8(0).is_ok());
    assert!(da_mode_from_u8(1).is_ok());
}

#[test]
fn test_parse_tip() {
    assert_eq!(parse_tip("0").unwrap(), 0);
    assert_eq!(parse_tip("100").unwrap(), 100);
    assert_eq!(parse_tip("0xff").unwrap(), 255);
}

#[test]
fn test_compute_typed_data_message_hash_wasm() {
    let json = serde_json::json!({
        "types": {
            "StarknetDomain": [
                { "name": "name", "type": "shortstring" },
                { "name": "version", "type": "shortstring" },
                { "name": "chainId", "type": "shortstring" },
                { "name": "revision", "type": "shortstring" }
            ],
            "Example": [
                { "name": "value", "type": "felt" }
            ]
        },
        "primaryType": "Example",
        "domain": {
            "name": "StarkNet",
            "version": "1",
            "chainId": "SN_MAIN",
            "revision": "1"
        },
        "message": {
            "value": "0x1"
        }
    });

    let result = compute_typed_data_message_hash(&json.to_string(), "0x1234");
    assert!(result.is_ok());
    let hash = result.unwrap();
    assert!(hash.starts_with("0x"));
    assert_ne!(hash, "0x0");

    // Must be deterministic.
    let result2 = compute_typed_data_message_hash(&json.to_string(), "0x1234");
    assert_eq!(hash, result2.unwrap());
}

#[test]
fn test_typed_data_different_accounts() {
    let json = serde_json::json!({
        "types": {
            "StarknetDomain": [
                { "name": "name", "type": "shortstring" },
                { "name": "version", "type": "shortstring" },
                { "name": "chainId", "type": "shortstring" },
                { "name": "revision", "type": "shortstring" }
            ],
            "Example": [
                { "name": "value", "type": "felt" }
            ]
        },
        "primaryType": "Example",
        "domain": {
            "name": "StarkNet",
            "version": "1",
            "chainId": "SN_MAIN",
            "revision": "1"
        },
        "message": {
            "value": "0x1"
        }
    });

    let hash1 = compute_typed_data_message_hash(&json.to_string(), "0x1111").unwrap();
    let hash2 = compute_typed_data_message_hash(&json.to_string(), "0x2222").unwrap();
    assert_ne!(hash1, hash2);
}

#[test]
fn test_resource_bound_input_parsing() {
    let input = ResourceBoundInput {
        max_amount: "1000".to_string(),
        max_price_per_unit: "500".to_string(),
    };
    let rb = input.to_resource_bounds().unwrap();
    assert_eq!(rb.max_amount, 1000);
    assert_eq!(rb.max_price_per_unit, 500);
}

#[test]
fn test_resource_bound_input_hex_parsing() {
    let input = ResourceBoundInput {
        max_amount: "0x3e8".to_string(),
        max_price_per_unit: "0x1f4".to_string(),
    };
    let rb = input.to_resource_bounds().unwrap();
    assert_eq!(rb.max_amount, 1000);
    assert_eq!(rb.max_price_per_unit, 500);
}
