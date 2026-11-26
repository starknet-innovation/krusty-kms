//! Refuse SNIP-12 documents the pinned encoder would hash differently from
//! starknet.js, before any hashing happens.

use super::super::{invalid_typed_data_error, CanonicalTypedDataEnvelope, RejectDuplicateKeys};
use krusty_kms_common::Result;
use serde::de::DeserializeSeed;

const PRESET_TYPE_NAMES: [&str; 3] = ["u256", "TokenAmount", "NftId"];

/// Names the pinned parser resolves to a built-in or preset in every revision.
const RESERVED_TYPE_NAMES: [&str; 15] = [
    "felt",
    "bool",
    "string",
    "selector",
    "merkletree",
    "enum",
    "u128",
    "i128",
    "ContractAddress",
    "ClassHash",
    "timestamp",
    "shortstring",
    "u256",
    "TokenAmount",
    "NftId",
];

pub(super) fn reject_duplicate_json_keys(json: &str) -> serde_json::Result<()> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    RejectDuplicateKeys.deserialize(&mut deserializer)?;
    deserializer.end()
}

/// starknet.js resolves a type string against the declared names verbatim, so
/// it can only agree with the pinned parser on names that parser reads back as
/// the same custom type: not reserved, not an array (`*`) or enum tuple, and
/// without surrounding whitespace, which the parser trims in enum variants.
fn is_plain_custom_type_name(name: &str) -> bool {
    !RESERVED_TYPE_NAMES.contains(&name)
        && !name.ends_with('*')
        && !name.contains(['(', ')', ','])
        && name.trim() == name
        && is_portable_name(name)
}

/// Revision 1 escapes `"`, `\` and control characters in type signatures
/// where starknet.js does not, and the two sort dependency names differently
/// (UTF-8 bytes versus UTF-16 units) only for characters above U+FFFF.
fn is_portable_name(name: &str) -> bool {
    !name
        .chars()
        .any(|c| c == '"' || c == '\\' || !(' '..='\u{FFFF}').contains(&c))
}

/// The pinned parser trims each type in an enum variant tuple such as
/// `(felt, felt)`; starknet.js keeps the spaces in the type signature.
fn has_padded_variant_type(field_type: &str) -> bool {
    field_type
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .is_some_and(|inner| inner.split(',').any(|part| part.trim() != part))
}

/// starknet.js lets a declared struct shadow a built-in type name, while the
/// pinned encoder always uses the built-in. On revision 0, starknet.js hashes
/// an undeclared preset as a felt and an enum definition as a struct, while the
/// pinned encoder applies the revision 1 meaning. Refuse rather than diverge.
pub(super) fn reject_unsupported_type_names(envelope: &CanonicalTypedDataEnvelope) -> Result<()> {
    let Some(types) = envelope.types.as_object() else {
        return Ok(());
    };
    let fields = || {
        types
            .values()
            .filter_map(serde_json::Value::as_array)
            .flatten()
    };
    if types.keys().any(|name| !is_plain_custom_type_name(name))
        || fields().any(|field| {
            field
                .get("name")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|name| !is_portable_name(name))
                || field
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(has_padded_variant_type)
        })
    {
        return Err(invalid_typed_data_error());
    }
    // The decoder selects revision 0 exactly when this legacy domain type is
    // declared, and rejects documents whose domain revision disagrees.
    if !types.contains_key("StarkNetDomain") {
        return Ok(());
    }
    let is_preset = |name: Option<&str>| {
        name.is_some_and(|name| PRESET_TYPE_NAMES.contains(&name.trim_end_matches('*')))
    };
    // An enum definition (variant types start with `(`) is hashed as a struct
    // by starknet.js revision 0 but as an enum by the pinned encoder.
    let revision_1_only = is_preset(envelope.primary_type.as_str())
        || fields().any(|field| {
            let field_type = field.get("type").and_then(serde_json::Value::as_str);
            field_type == Some("enum")
                || field_type.is_some_and(|t| t.trim_start().starts_with('('))
                || is_preset(field_type)
                || is_preset(field.get("contains").and_then(serde_json::Value::as_str))
        });
    if revision_1_only {
        return Err(invalid_typed_data_error());
    }
    Ok(())
}
