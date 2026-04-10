//! SNIP-12 typed data message hash computation.
//!
//! Implements the Starknet equivalent of EIP-712, allowing off-chain typed
//! structured data to be hashed in a domain-separated, collision-resistant
//! manner suitable for signing.

use std::collections::{BTreeSet, HashMap};

use serde::Deserialize;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use krusty_kms_common::Result;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute the SNIP-12 message hash for the given typed-data JSON and account.
///
/// This is the value that should be signed to produce a valid SNIP-12
/// signature over the typed data message.
///
/// # Arguments
/// * `typed_data_json` - JSON string conforming to the SNIP-12 typed data
///   schema (types, primaryType, domain, message).
/// * `account_address` - The signer's Starknet account address.
///
/// # Returns
/// The Poseidon hash that should be signed.
pub fn compute_typed_data_message_hash(
    typed_data_json: &str,
    account_address: &Felt,
) -> Result<Felt> {
    let typed_data: TypedData = serde_json::from_str(typed_data_json)?;

    let domain_hash = struct_hash("StarknetDomain", &typed_data.domain, &typed_data.types)?;
    let message_hash = struct_hash(
        &typed_data.primary_type,
        &typed_data.message,
        &typed_data.types,
    )?;

    let prefix = starknet_keccak(b"StarkNet Message");

    Ok(Poseidon::hash_array(&[
        prefix,
        domain_hash,
        *account_address,
        message_hash,
    ]))
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TypedData {
    types: HashMap<String, Vec<TypeMember>>,
    primary_type: String,
    domain: serde_json::Value,
    message: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct TypeMember {
    name: String,
    #[serde(rename = "type")]
    type_: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a Starknet-flavoured Keccak256 (top 6 bits masked to fit 250 bits).
fn starknet_keccak(data: &[u8]) -> Felt {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    // Mask the top 6 bits so the result fits in a 250-bit Stark field element.
    bytes[0] &= 0x03;
    Felt::from_bytes_be_slice(&bytes)
}

/// Produce the canonical type encoding string for `type_name`.
///
/// For a type `T` with fields `(f1:t1, f2:t2, ...)` the encoding is:
///   `T(f1:t1,f2:t2,...)`
///
/// If any field type is itself a struct defined in `types`, those referenced
/// types are appended (sorted alphabetically, deduplicated).
fn encode_type(type_name: &str, types: &HashMap<String, Vec<TypeMember>>) -> String {
    let members = match types.get(type_name) {
        Some(m) => m,
        None => return String::new(),
    };

    let self_encoding = format!(
        "\"{}\"({})",
        type_name,
        members
            .iter()
            .map(|m| format!("\"{}\":\"{}\"", m.name, m.type_))
            .collect::<Vec<_>>()
            .join(",")
    );

    // Collect referenced struct types (excluding self to avoid duplication).
    let mut referenced = BTreeSet::new();
    collect_referenced_types(type_name, types, &mut referenced);
    referenced.remove(type_name);

    let mut result = self_encoding;
    for dep in &referenced {
        if let Some(dep_members) = types.get(dep.as_str()) {
            result.push_str(&format!(
                "\"{}\"({})",
                dep,
                dep_members
                    .iter()
                    .map(|m| format!("\"{}\":\"{}\"", m.name, m.type_))
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
    }

    result
}

/// Recursively collect all struct types referenced by `type_name`.
fn collect_referenced_types(
    type_name: &str,
    types: &HashMap<String, Vec<TypeMember>>,
    out: &mut BTreeSet<String>,
) {
    let members = match types.get(type_name) {
        Some(m) => m,
        None => return,
    };

    for member in members {
        let base_type = strip_array_suffix(&member.type_);
        if types.contains_key(base_type) && !out.contains(base_type) {
            out.insert(base_type.to_string());
            collect_referenced_types(base_type, types, out);
        }
    }
}

/// Strip a trailing `*` (array marker) from a type name.
fn strip_array_suffix(type_name: &str) -> &str {
    type_name.strip_suffix('*').unwrap_or(type_name)
}

/// Compute the type hash: `starknet_keccak(encode_type(name, types))`.
fn type_hash(type_name: &str, types: &HashMap<String, Vec<TypeMember>>) -> Felt {
    let encoded = encode_type(type_name, types);
    starknet_keccak(encoded.as_bytes())
}

/// Compute the struct hash for a typed value:
/// `Poseidon::hash_array(&[type_hash, encoded_field_1, encoded_field_2, ...])`
fn struct_hash(
    type_name: &str,
    value: &serde_json::Value,
    types: &HashMap<String, Vec<TypeMember>>,
) -> Result<Felt> {
    let members = types.get(type_name).ok_or_else(|| {
        krusty_kms_common::KmsError::SerializationError(format!(
            "Unknown type in typed data: {type_name}"
        ))
    })?;

    let th = type_hash(type_name, types);
    let mut elements = vec![th];

    for member in members {
        let field_value = &value[&member.name];
        let encoded = encode_value(&member.type_, field_value, types)?;
        elements.extend(encoded);
    }

    Ok(Poseidon::hash_array(&elements))
}

/// Encode a single value according to its SNIP-12 type.
///
/// Returns one or more `Felt` values (most types produce exactly one; `u256`
/// produces two: `[low, high]`).
fn encode_value(
    type_name: &str,
    value: &serde_json::Value,
    types: &HashMap<String, Vec<TypeMember>>,
) -> Result<Vec<Felt>> {
    // --- Array types (ending with `*`) ---
    if let Some(elem_type) = type_name.strip_suffix('*') {
        let arr = value.as_array().ok_or_else(|| {
            krusty_kms_common::KmsError::SerializationError(format!(
                "Expected array for type {type_name}"
            ))
        })?;
        let mut inner = Vec::new();
        for elem in arr {
            inner.extend(encode_value(elem_type, elem, types)?);
        }
        return Ok(vec![Poseidon::hash_array(&inner)]);
    }

    // --- Enum types (contain parentheses like "MyEnum(Variant1,Variant2)") ---
    if type_name.contains('(') && type_name.contains(')') {
        return encode_enum_value(type_name, value, types);
    }

    // --- Struct types (defined in the types map) ---
    if types.contains_key(type_name) {
        let h = struct_hash(type_name, value, types)?;
        return Ok(vec![h]);
    }

    // --- Scalar / basic types ---
    match type_name {
        "felt" | "ContractAddress" | "ClassHash" | "EthAddress" | "timestamp" => {
            Ok(vec![parse_felt_from_json(value)?])
        }
        "u128" => Ok(vec![parse_felt_from_json(value)?]),
        "i128" => {
            // i128: if negative, add PRIME implicitly; for now just parse as felt.
            Ok(vec![parse_felt_from_json(value)?])
        }
        "u256" => {
            // Encode as two felts: [low_128, high_128].
            let big = parse_u256_from_json(value)?;
            let mask_128 = (num_bigint::BigUint::from(1u128) << 128) - 1u32;
            let low = &big & &mask_128;
            let high = &big >> 128;
            let low_felt = felt_from_biguint(&low);
            let high_felt = felt_from_biguint(&high);
            Ok(vec![low_felt, high_felt])
        }
        "bool" => {
            let b = value.as_bool().ok_or_else(|| {
                krusty_kms_common::KmsError::SerializationError("Expected bool value".to_string())
            })?;
            Ok(vec![if b { Felt::ONE } else { Felt::ZERO }])
        }
        "shortstring" => {
            let s = value.as_str().ok_or_else(|| {
                krusty_kms_common::KmsError::SerializationError(
                    "Expected string for shortstring".to_string(),
                )
            })?;
            Ok(vec![Felt::from_bytes_be_slice(s.as_bytes())])
        }
        "string" => {
            let s = value.as_str().ok_or_else(|| {
                krusty_kms_common::KmsError::SerializationError("Expected string value".to_string())
            })?;
            Ok(vec![starknet_keccak(s.as_bytes())])
        }
        "merkletree" => {
            // The value is a pre-computed root.
            Ok(vec![parse_felt_from_json(value)?])
        }
        "NoneType" => Ok(vec![Poseidon::hash_array(&[])]),
        _ => Err(krusty_kms_common::KmsError::SerializationError(format!(
            "Unsupported SNIP-12 type: {type_name}"
        ))),
    }
}

/// Encode an enum value.
///
/// Enum type strings look like `"MyEnum(Variant1,Variant2)"`. The JSON value
/// is expected to be an object with a single key matching one of the variants.
fn encode_enum_value(
    type_name: &str,
    value: &serde_json::Value,
    types: &HashMap<String, Vec<TypeMember>>,
) -> Result<Vec<Felt>> {
    // Parse "EnumName(V1,V2,...)" into name and variants.
    let paren_idx = type_name.find('(').ok_or_else(|| {
        krusty_kms_common::KmsError::SerializationError(format!("Malformed enum type: {type_name}"))
    })?;
    let _enum_name = &type_name[..paren_idx];
    let variants_str = &type_name[paren_idx + 1..type_name.len() - 1];
    let variants: Vec<&str> = variants_str.split(',').collect();

    let th = starknet_keccak(type_name.as_bytes());

    let obj = value.as_object().ok_or_else(|| {
        krusty_kms_common::KmsError::SerializationError(
            "Expected object for enum value".to_string(),
        )
    })?;

    let (variant_key, variant_value) = obj.iter().next().ok_or_else(|| {
        krusty_kms_common::KmsError::SerializationError(
            "Enum object must have exactly one key".to_string(),
        )
    })?;

    let variant_index = variants
        .iter()
        .position(|v| v.trim() == variant_key)
        .ok_or_else(|| {
            krusty_kms_common::KmsError::SerializationError(format!(
                "Unknown enum variant: {variant_key}"
            ))
        })?;

    let mut elements = vec![th, Felt::from(variant_index as u64)];

    // Encode the variant data. If it's an array, encode each element; if it's
    // a single value, encode it directly. For tuple-style variants the value
    // is typically an array; for unit variants it may be null.
    if variant_value.is_array() {
        for elem in variant_value.as_array().unwrap() {
            elements.extend(encode_value("felt", elem, types)?);
        }
    } else if !variant_value.is_null() {
        elements.extend(encode_value("felt", variant_value, types)?);
    }

    Ok(vec![Poseidon::hash_array(&elements)])
}

/// Parse a felt from a JSON value (hex string, decimal string, or number).
fn parse_felt_from_json(value: &serde_json::Value) -> Result<Felt> {
    match value {
        serde_json::Value::String(s) => {
            if s.starts_with("0x") || s.starts_with("0X") {
                Felt::from_hex(s).map_err(|e| {
                    krusty_kms_common::KmsError::SerializationError(format!(
                        "Invalid hex felt: {e}"
                    ))
                })
            } else {
                // Decimal string
                Felt::from_dec_str(s).map_err(|e| {
                    krusty_kms_common::KmsError::SerializationError(format!(
                        "Invalid decimal felt: {e}"
                    ))
                })
            }
        }
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(Felt::from(u))
            } else {
                Err(krusty_kms_common::KmsError::SerializationError(format!(
                    "Number out of range for felt: {n}"
                )))
            }
        }
        _ => Err(krusty_kms_common::KmsError::SerializationError(format!(
            "Cannot parse felt from: {value}"
        ))),
    }
}

/// Parse a u256 from a JSON value.
fn parse_u256_from_json(value: &serde_json::Value) -> Result<num_bigint::BigUint> {
    use num_traits::Num;

    // If the value is an object with "low" and "high" keys, combine them.
    if let Some(obj) = value.as_object() {
        if let (Some(low_val), Some(high_val)) = (obj.get("low"), obj.get("high")) {
            let low = parse_u256_from_json(low_val)?;
            let high = parse_u256_from_json(high_val)?;
            return Ok((high << 128) | low);
        }
    }

    match value {
        serde_json::Value::String(s) => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                num_bigint::BigUint::from_str_radix(hex, 16).map_err(|e| {
                    krusty_kms_common::KmsError::SerializationError(format!(
                        "Invalid hex u256: {e}"
                    ))
                })
            } else {
                num_bigint::BigUint::from_str_radix(s, 10).map_err(|e| {
                    krusty_kms_common::KmsError::SerializationError(format!(
                        "Invalid decimal u256: {e}"
                    ))
                })
            }
        }
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(num_bigint::BigUint::from(u))
            } else {
                Err(krusty_kms_common::KmsError::SerializationError(format!(
                    "Number out of range for u256: {n}"
                )))
            }
        }
        _ => Err(krusty_kms_common::KmsError::SerializationError(format!(
            "Cannot parse u256 from: {value}"
        ))),
    }
}

/// Convert a `BigUint` to a `Felt`.
fn felt_from_biguint(n: &num_bigint::BigUint) -> Felt {
    let bytes = n.to_bytes_be();
    Felt::from_bytes_be_slice(&bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_type_starknet_domain() {
        let mut types = HashMap::new();
        types.insert(
            "StarknetDomain".to_string(),
            vec![
                TypeMember {
                    name: "name".to_string(),
                    type_: "shortstring".to_string(),
                },
                TypeMember {
                    name: "version".to_string(),
                    type_: "shortstring".to_string(),
                },
                TypeMember {
                    name: "chainId".to_string(),
                    type_: "shortstring".to_string(),
                },
                TypeMember {
                    name: "revision".to_string(),
                    type_: "shortstring".to_string(),
                },
            ],
        );

        let encoded = encode_type("StarknetDomain", &types);
        assert_eq!(
            encoded,
            "\"StarknetDomain\"(\"name\":\"shortstring\",\"version\":\"shortstring\",\"chainId\":\"shortstring\",\"revision\":\"shortstring\")"
        );
    }

    #[test]
    fn test_type_hash_is_deterministic() {
        let mut types = HashMap::new();
        types.insert(
            "StarknetDomain".to_string(),
            vec![
                TypeMember {
                    name: "name".to_string(),
                    type_: "shortstring".to_string(),
                },
                TypeMember {
                    name: "version".to_string(),
                    type_: "shortstring".to_string(),
                },
            ],
        );

        let h1 = type_hash("StarknetDomain", &types);
        let h2 = type_hash("StarknetDomain", &types);
        assert_eq!(h1, h2);
        assert_ne!(h1, Felt::ZERO);
    }

    #[test]
    fn test_starknet_keccak_fits_250_bits() {
        let hash = starknet_keccak(b"StarkNet Message");
        // The top 6 bits should be cleared (byte[0] & 0xFC == 0).
        let bytes = hash.to_bytes_be();
        assert_eq!(bytes[0] & 0xFC, 0);
    }

    #[test]
    fn test_compute_typed_data_message_hash_simple() {
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

        let account = Felt::from(0x1234u64);
        let hash =
            compute_typed_data_message_hash(&json.to_string(), &account).expect("should compute");
        assert_ne!(hash, Felt::ZERO);

        // Must be deterministic.
        let hash2 =
            compute_typed_data_message_hash(&json.to_string(), &account).expect("should compute");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_compute_typed_data_with_u256() {
        let json = serde_json::json!({
            "types": {
                "StarknetDomain": [
                    { "name": "name", "type": "shortstring" },
                    { "name": "version", "type": "shortstring" },
                    { "name": "chainId", "type": "shortstring" },
                    { "name": "revision", "type": "shortstring" }
                ],
                "Transfer": [
                    { "name": "amount", "type": "u256" },
                    { "name": "recipient", "type": "ContractAddress" }
                ]
            },
            "primaryType": "Transfer",
            "domain": {
                "name": "StarkNet",
                "version": "1",
                "chainId": "SN_MAIN",
                "revision": "1"
            },
            "message": {
                "amount": { "low": "0x100", "high": "0x0" },
                "recipient": "0xdeadbeef"
            }
        });

        let account = Felt::from(0xABCDu64);
        let hash =
            compute_typed_data_message_hash(&json.to_string(), &account).expect("should compute");
        assert_ne!(hash, Felt::ZERO);
    }

    #[test]
    fn test_encode_type_with_nested_struct() {
        let mut types = HashMap::new();
        types.insert(
            "Order".to_string(),
            vec![
                TypeMember {
                    name: "price".to_string(),
                    type_: "felt".to_string(),
                },
                TypeMember {
                    name: "item".to_string(),
                    type_: "Item".to_string(),
                },
            ],
        );
        types.insert(
            "Item".to_string(),
            vec![TypeMember {
                name: "name".to_string(),
                type_: "shortstring".to_string(),
            }],
        );

        let encoded = encode_type("Order", &types);
        // The primary type comes first, then referenced types sorted alphabetically.
        assert!(encoded.starts_with("\"Order\"("));
        assert!(encoded.contains("\"Item\"("));
    }

    #[test]
    fn test_bool_encoding() {
        let true_val = serde_json::Value::Bool(true);
        let false_val = serde_json::Value::Bool(false);
        let types = HashMap::new();

        let t = encode_value("bool", &true_val, &types).unwrap();
        let f = encode_value("bool", &false_val, &types).unwrap();

        assert_eq!(t, vec![Felt::ONE]);
        assert_eq!(f, vec![Felt::ZERO]);
    }

    #[test]
    fn test_shortstring_encoding() {
        let val = serde_json::Value::String("hello".to_string());
        let types = HashMap::new();
        let result = encode_value("shortstring", &val, &types).unwrap();
        assert_eq!(result, vec![Felt::from_bytes_be_slice(b"hello")]);
    }

    #[test]
    fn test_string_encoding() {
        let val = serde_json::Value::String("hello world".to_string());
        let types = HashMap::new();
        let result = encode_value("string", &val, &types).unwrap();
        assert_eq!(result, vec![starknet_keccak(b"hello world")]);
    }

    #[test]
    fn test_different_accounts_produce_different_hashes() {
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

        let account1 = Felt::from(0x1111u64);
        let account2 = Felt::from(0x2222u64);

        let hash1 = compute_typed_data_message_hash(&json.to_string(), &account1).unwrap();
        let hash2 = compute_typed_data_message_hash(&json.to_string(), &account2).unwrap();

        assert_ne!(hash1, hash2);
    }
}
