//! Narrow starknet.js compatibility for values the pinned SNIP-12 encoder differs on.

use super::{
    invalid_typed_data_error, CanonicalTypedDataEnvelope, RejectDuplicateKeys,
    MAX_TYPED_DATA_JSON_BYTES,
};
use krusty_kms_common::{KmsError, Result};
use serde::de::DeserializeSeed;
use starknet_crypto::{pedersen_hash, poseidon_hash, poseidon_hash_many};
use starknet_rust_core::{
    crypto::compute_hash_on_elements,
    types::typed_data::{
        CommonTypeReference, Encoder, EnumDefinition, FullTypeReference, ObjectValue, Revision,
        StructDefinition, TypeDefinition, TypeReference, Value,
    },
    types::TypedData as StarknetTypedData,
    utils::{cairo_short_string_to_felt, starknet_keccak},
};
use starknet_types_core::felt::Felt;

fn reject_duplicate_json_keys(json: &str) -> serde_json::Result<()> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    RejectDuplicateKeys.deserialize(&mut deserializer)?;
    deserializer.end()
}

pub(super) fn compute_typed_data_message_hash_impl(
    typed_data_json: &str,
    account_address: &Felt,
) -> Result<Felt> {
    if typed_data_json.len() > MAX_TYPED_DATA_JSON_BYTES {
        return Err(KmsError::SerializationError(format!(
            "typed data JSON exceeds the {} byte limit",
            MAX_TYPED_DATA_JSON_BYTES
        )));
    }

    reject_duplicate_json_keys(typed_data_json).map_err(|_| invalid_typed_data_error())?;
    let mut envelope: CanonicalTypedDataEnvelope =
        serde_json::from_str(typed_data_json).map_err(|_| invalid_typed_data_error())?;
    // starknet.js allows a revision field in a legacy domain type. The pinned
    // Rust decoder insists on the three-field definition, so remove only this
    // known extra field for decoding and retain it for the domain hash.
    let legacy_revision_field = strip_legacy_revision_field(&mut envelope)?;
    let domain = serde_json::to_value(&envelope.domain).map_err(|_| invalid_typed_data_error())?;
    let domain_type_name = if envelope.types.get("StarkNetDomain").is_some() {
        "StarkNetDomain"
    } else {
        "StarknetDomain"
    };
    let domain_type = envelope
        .types
        .get(domain_type_name)
        .cloned()
        .ok_or_else(invalid_typed_data_error)?;
    let typed_data: StarknetTypedData = serde_json::from_value(
        serde_json::to_value(envelope).map_err(|_| invalid_typed_data_error())?,
    )
    .map_err(|_| invalid_typed_data_error())?;
    message_hash(
        &typed_data,
        *account_address,
        &domain_type,
        &domain,
        legacy_revision_field,
    )
}

/// The legacy domain type may declare `revision: felt` when its value is "0".
/// Keep the declaration's presence so its four-field type hash is used below.
pub(super) fn strip_legacy_revision_field(
    envelope: &mut CanonicalTypedDataEnvelope,
) -> Result<bool> {
    if envelope.domain.revision.as_ref() != Some(&serde_json::json!("0")) {
        return Ok(false);
    }
    let Some(fields) = envelope
        .types
        .get_mut("StarkNetDomain")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Ok(false);
    };
    if fields.len() == 4 && fields[3] == serde_json::json!({"name":"revision","type":"felt"}) {
        fields.pop();
        return Ok(true);
    }
    Ok(false)
}

pub(super) fn message_hash(
    typed_data: &StarknetTypedData,
    address: Felt,
    domain_type: &serde_json::Value,
    domain: &serde_json::Value,
    legacy_revision_field: bool,
) -> Result<Felt> {
    let encoder = typed_data.encoder();
    let domain_name = match typed_data.revision() {
        Revision::V0 => "StarkNetDomain",
        Revision::V1 => "StarknetDomain",
    };
    let definition = domain_definition(typed_data.revision(), legacy_revision_field);
    // The decoder validated the domain type after removing the one supported
    // legacy extension. Reject any unexpected shape before hashing it.
    let expected_len = definition.fields.len();
    let actual_len = domain_type
        .as_array()
        .map(std::vec::Vec::len)
        .ok_or_else(invalid_typed_data_error)?;
    if actual_len != expected_len - usize::from(legacy_revision_field) {
        return Err(invalid_typed_data_error());
    }
    let mut domain_for_hash = domain.clone();
    if typed_data.revision() == Revision::V0 && !legacy_revision_field {
        // A three-field legacy domain may still supply revision "0". As in
        // starknet.js, only fields declared by the type contribute to its hash.
        domain_for_hash
            .as_object_mut()
            .ok_or_else(invalid_typed_data_error)?
            .remove("revision");
    }
    let domain_value: Value =
        serde_json::from_value(domain_for_hash).map_err(|_| invalid_typed_data_error())?;
    let domain_hash = encode_domain(encoder, &definition, &domain_value, legacy_revision_field)?;
    let message_hash = if typed_data.primary_type().common().is_domain(domain_name) {
        encode_domain(
            encoder,
            &definition,
            typed_data.message(),
            legacy_revision_field,
        )?
    } else {
        encode_value(encoder, typed_data.primary_type(), typed_data.message())?
    };
    let prefix =
        cairo_short_string_to_felt("StarkNet Message").map_err(|_| invalid_typed_data_error())?;
    Ok(hash_elements(
        typed_data.revision(),
        &[prefix, domain_hash, address, message_hash],
    ))
}

trait DomainReference {
    fn is_domain(&self, domain_name: &str) -> bool;
}

impl DomainReference for CommonTypeReference<'_> {
    fn is_domain(&self, domain_name: &str) -> bool {
        matches!(self, Self::Custom(name) if *name == domain_name)
    }
}

fn domain_definition(revision: Revision, legacy_revision_field: bool) -> StructDefinition {
    let field_type = match revision {
        Revision::V0 => FullTypeReference::Felt,
        Revision::V1 => FullTypeReference::ShortString,
    };
    let mut fields = ["name", "version", "chainId"]
        .into_iter()
        .map(|name| {
            starknet_rust_core::types::typed_data::FieldDefinition::new(
                name.into(),
                field_type.clone(),
            )
        })
        .collect::<Vec<_>>();
    if revision == Revision::V1 || legacy_revision_field {
        fields.push(starknet_rust_core::types::typed_data::FieldDefinition::new(
            "revision".into(),
            field_type,
        ));
    }
    StructDefinition { fields }
}

fn encode_domain(
    encoder: &Encoder,
    definition: &StructDefinition,
    value: &Value,
    legacy_revision_field: bool,
) -> Result<Felt> {
    let signature = match (encoder.revision(), legacy_revision_field) {
        (Revision::V0, false) => "StarkNetDomain(name:felt,version:felt,chainId:felt)",
        (Revision::V0, true) => "StarkNetDomain(name:felt,version:felt,chainId:felt,revision:felt)",
        (Revision::V1, false) => "\"StarknetDomain\"(\"name\":\"shortstring\",\"version\":\"shortstring\",\"chainId\":\"shortstring\",\"revision\":\"shortstring\")",
        (Revision::V1, true) => return Err(invalid_typed_data_error()),
    };
    let type_hash = starknet_keccak(signature.as_bytes());
    encode_struct(encoder, type_hash, definition, value)
}

fn hash_elements(revision: Revision, elements: &[Felt]) -> Felt {
    match revision {
        Revision::V0 => compute_hash_on_elements(elements),
        Revision::V1 => poseidon_hash_many(elements),
    }
}

fn hash_pair(revision: Revision, a: Felt, b: Felt) -> Felt {
    match revision {
        Revision::V0 => pedersen_hash(&a, &b),
        Revision::V1 => poseidon_hash(a, b),
    }
}

fn encode_struct(
    encoder: &Encoder,
    type_hash: Felt,
    definition: &StructDefinition,
    value: &Value,
) -> Result<Felt> {
    let Value::Object(object) = value else {
        return Err(invalid_typed_data_error());
    };
    if object.fields.len() != definition.fields.len() {
        return Err(invalid_typed_data_error());
    }
    let mut encoded = Vec::with_capacity(definition.fields.len() + 1);
    encoded.push(type_hash);
    for field in &definition.fields {
        let value = object
            .fields
            .get(&field.name)
            .ok_or_else(invalid_typed_data_error)?;
        encoded.push(encode_value(encoder, &field.r#type, value)?);
    }
    Ok(hash_elements(encoder.revision(), &encoded))
}

fn encode_enum(
    encoder: &Encoder,
    definition: &EnumDefinition,
    value: &ObjectValue,
) -> Result<Felt> {
    if value.fields.len() != 1 {
        return Err(invalid_typed_data_error());
    }
    let (variant_name, tuple) = value.fields.first().ok_or_else(invalid_typed_data_error)?;
    let (index, variant) = definition
        .variants
        .iter()
        .enumerate()
        .find(|(_, variant)| variant.name == *variant_name)
        .ok_or_else(invalid_typed_data_error)?;
    let Value::Array(tuple) = tuple else {
        return Err(invalid_typed_data_error());
    };
    if tuple.elements.len() != variant.tuple_types.len() {
        return Err(invalid_typed_data_error());
    }
    let mut encoded = vec![Felt::from(index)];
    for (type_ref, value) in variant.tuple_types.iter().zip(&tuple.elements) {
        encoded.push(encode_value(encoder, type_ref, value)?);
    }
    Ok(hash_elements(encoder.revision(), &encoded))
}

fn encode_merkle(
    encoder: &Encoder,
    leaf_type: &starknet_rust_core::types::typed_data::InlineTypeReference,
    value: &Value,
) -> Result<Felt> {
    let Value::Array(leaves) = value else {
        return Err(invalid_typed_data_error());
    };
    if leaves.elements.is_empty() {
        return Err(invalid_typed_data_error());
    }
    let mut layer = leaves
        .elements
        .iter()
        .map(|leaf| encode_value(encoder, leaf_type, leaf))
        .collect::<Result<Vec<_>>>()?;
    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => hash_pair(encoder.revision(), (*a).min(*b), (*a).max(*b)),
                [a] => hash_pair(encoder.revision(), Felt::ZERO, *a),
                _ => unreachable!(),
            })
            .collect();
    }
    Ok(layer[0])
}

fn encode_value<R: TypeReference>(encoder: &Encoder, type_ref: &R, value: &Value) -> Result<Felt> {
    match type_ref.common() {
        CommonTypeReference::Custom(name) => {
            let definition = encoder
                .types()
                .get_type(name)
                .ok_or_else(invalid_typed_data_error)?;
            match definition {
                TypeDefinition::Struct(definition) if !type_ref.must_be_enum() => encode_struct(
                    encoder,
                    encoder
                        .types()
                        .get_type_hash(name)
                        .map_err(|_| invalid_typed_data_error())?,
                    definition,
                    value,
                ),
                TypeDefinition::Enum(definition) if !type_ref.must_be_struct() => {
                    let Value::Object(object) = value else {
                        return Err(invalid_typed_data_error());
                    };
                    encode_enum(encoder, definition, object)
                }
                _ => Err(invalid_typed_data_error()),
            }
        }
        CommonTypeReference::Array(element) => {
            let Value::Array(array) = value else {
                return Err(invalid_typed_data_error());
            };
            let encoded = array
                .elements
                .iter()
                .map(|item| encode_value(encoder, element, item))
                .collect::<Result<Vec<_>>>()?;
            Ok(hash_elements(encoder.revision(), &encoded))
        }
        CommonTypeReference::MerkleTree(leaf) => encode_merkle(encoder, leaf, value),
        _ => encode_primitive(encoder, type_ref, value),
    }
}

fn encode_primitive<R: TypeReference>(
    encoder: &Encoder,
    type_ref: &R,
    value: &Value,
) -> Result<Felt> {
    match type_ref.common() {
        CommonTypeReference::I128 => {
            let integer = match value {
                Value::SignedInteger(value) => *value,
                Value::UnsignedInteger(value) => {
                    i128::try_from(*value).map_err(|_| invalid_typed_data_error())?
                }
                Value::String(value) => value
                    .parse::<i128>()
                    .map_err(|_| invalid_typed_data_error())?,
                _ => return Err(invalid_typed_data_error()),
            };
            encoder
                .encode_value(type_ref, &Value::SignedInteger(integer))
                .map_err(|_| invalid_typed_data_error())
        }
        CommonTypeReference::Felt | CommonTypeReference::ShortString => {
            if let Value::String(raw) = value {
                if let Some(hex) = raw.strip_prefix("0X") {
                    if !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        return encoder
                            .encode_value(type_ref, &Value::String(format!("0x{hex}")))
                            .map_err(|_| invalid_typed_data_error());
                    }
                }
            }
            encoder
                .encode_value(type_ref, value)
                .map_err(|_| invalid_typed_data_error())
        }
        CommonTypeReference::Selector => {
            if let Value::String(raw) = value {
                if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
                    if hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        if hex.is_empty() {
                            return Err(invalid_typed_data_error());
                        }
                        return Felt::from_hex(&format!("0x{hex}"))
                            .map_err(|_| invalid_typed_data_error());
                    }
                }
            }
            encoder
                .encode_value(type_ref, value)
                .map_err(|_| invalid_typed_data_error())
        }
        _ => encoder
            .encode_value(type_ref, value)
            .map_err(|_| invalid_typed_data_error()),
    }
}
