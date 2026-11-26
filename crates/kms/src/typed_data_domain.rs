//! SNIP-12 domain handling: the signed domain value, and decoding a document
//! whose domain is hashed from its declared type, as starknet.js does.

use super::invalid_typed_data_error;
use krusty_kms_common::Result;
use serde_json::json;
use starknet_rust_core::{
    types::typed_data::{
        FullTypeReference, Revision, StructDefinition, TypeDefinition, TypeReference,
    },
    types::TypedData as StarknetTypedData,
    utils::starknet_keccak,
};
use starknet_types_core::felt::Felt;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CanonicalTypedDataDomain {
    // `present` keeps an explicit null as `Some(Null)`, so it is rejected
    // rather than treated as an absent, undeclared field.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    name: Option<serde_json::Value>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    version: Option<serde_json::Value>,
    #[serde(
        default,
        rename = "chainId",
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    chain_id: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) revision: Option<serde_json::Value>,
}

fn present<'de, D>(deserializer: D) -> std::result::Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

/// Basic and preset SNIP-12 type names of either revision.
const BUILT_IN_TYPE_NAMES: [&str; 15] = [
    "felt",
    "shortstring",
    "selector",
    "string",
    "bool",
    "u128",
    "i128",
    "u256",
    "ContractAddress",
    "ClassHash",
    "timestamp",
    "merkletree",
    "enum",
    "TokenAmount",
    "NftId",
];

/// Decode everything but the domain with the pinned decoder, and parse the
/// declared domain type for `compute_typed_data_message_hash_impl`.
pub(super) fn decode(
    revision: Revision,
    mut types: serde_json::Map<String, serde_json::Value>,
    primary_type: serde_json::Value,
    message: serde_json::Value,
) -> Result<(StarknetTypedData, StructDefinition)> {
    let (domain_name, other_domain_name, decoder_domain_type, decoder_domain) = match revision {
        Revision::V0 => (
            "StarkNetDomain",
            "StarknetDomain",
            json!([
                {"name": "name", "type": "felt"},
                {"name": "version", "type": "felt"},
                {"name": "chainId", "type": "felt"}
            ]),
            json!({"name": "0", "version": "0", "chainId": "0"}),
        ),
        Revision::V1 => (
            "StarknetDomain",
            "StarkNetDomain",
            json!([
                {"name": "name", "type": "shortstring"},
                {"name": "version", "type": "shortstring"},
                {"name": "chainId", "type": "shortstring"},
                {"name": "revision", "type": "shortstring"}
            ]),
            json!({"name": "0", "version": "0", "chainId": "0", "revision": "1"}),
        ),
    };
    let domain_type = types
        .remove(domain_name)
        .ok_or_else(invalid_typed_data_error)?;
    let definition = domain_definition(revision, domain_type)?;
    // The caller hashes the domain from its declared type, as starknet.js does.
    // The pinned decoder accepts only the canonical domain type, so it gets
    // that and placeholder values. starknet.js also ignores types the primary
    // type never reaches, but the decoder refuses the other revision's domain
    // type and empty structs: drop those, so a reference to one fails closed
    // as an undefined type.
    //
    // starknet.js lets a declared type shadow a built-in one, and rejects
    // preset names. The pinned decoder resolves those names to the built-in
    // types instead, so refuse them all rather than hash a different digest.
    if types
        .keys()
        .any(|name| BUILT_IN_TYPE_NAMES.contains(&name.as_str()))
    {
        return Err(invalid_typed_data_error());
    }
    types.remove(other_domain_name);
    types.retain(|_, type_def| type_def.as_array().is_none_or(|fields| !fields.is_empty()));
    types.insert(domain_name.to_owned(), decoder_domain_type);
    let typed_data: StarknetTypedData = serde_json::from_value(json!({
        "types": types,
        "domain": decoder_domain,
        "primaryType": primary_type,
        "message": message,
    }))
    .map_err(|_| invalid_typed_data_error())?;

    Ok((typed_data, definition))
}

/// Parse a declared domain type. Fields may be any subset of the four domain
/// fields in any order, typed `felt` (and `shortstring` in revision 1), as
/// starknet.js accepts. The decoder rejects an empty definition.
fn domain_definition(revision: Revision, declared: serde_json::Value) -> Result<StructDefinition> {
    let Ok(TypeDefinition::Struct(definition)) = serde_json::from_value(declared) else {
        return Err(invalid_typed_data_error());
    };
    let mut seen = Vec::with_capacity(definition.fields.len());
    for field in &definition.fields {
        let known_name = ["name", "version", "chainId", "revision"].contains(&field.name.as_str());
        let allowed_type = match field.r#type {
            FullTypeReference::Felt => true,
            FullTypeReference::ShortString => revision == Revision::V1,
            _ => false,
        };
        if !known_name || !allowed_type || seen.contains(&&field.name) {
            return Err(invalid_typed_data_error());
        }
        seen.push(&field.name);
    }
    Ok(definition)
}

pub(super) fn domain_type_hash(
    revision: Revision,
    name: &str,
    definition: &StructDefinition,
) -> Felt {
    let quote = match revision {
        Revision::V0 => "",
        Revision::V1 => "\"",
    };
    let fields = definition
        .fields
        .iter()
        .map(|field| {
            format!(
                "{quote}{}{quote}:{quote}{}{quote}",
                field.name,
                field.r#type.signature_ref_repr()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    starknet_keccak(format!("{quote}{name}{quote}({fields})").as_bytes())
}
