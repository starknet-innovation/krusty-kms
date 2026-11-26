//! Narrow starknet.js compatibility for values the pinned SNIP-12 encoder differs on.

use super::{
    domain::{decode, domain_type_hash},
    invalid_typed_data_error, CanonicalTypedDataEnvelope, RejectDuplicateKeys,
    MAX_TYPED_DATA_JSON_BYTES,
};
use krusty_kms_common::{KmsError, Result};
use serde::de::DeserializeSeed;
use starknet_crypto::{pedersen_hash, poseidon_hash, poseidon_hash_many};
use starknet_rust_core::{
    crypto::compute_hash_on_elements,
    types::typed_data::{
        CommonTypeReference, Encoder, EnumDefinition, ObjectValue, Revision, StructDefinition,
        TypeDefinition, TypeReference, Value,
    },
    utils::cairo_short_string_to_felt,
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
    let envelope: CanonicalTypedDataEnvelope =
        serde_json::from_str(typed_data_json).map_err(|_| invalid_typed_data_error())?;
    // As in starknet.js, the domain's revision value selects the revision and
    // so which domain type applies.
    let revision = match &envelope.domain.revision {
        None => Revision::V0,
        Some(value) => {
            serde_json::from_value(value.clone()).map_err(|_| invalid_typed_data_error())?
        }
    };
    // starknet.js accepts revision 0 only as an absent value or the string
    // "0"; the pinned decoder also accepts the number 0.
    if revision == Revision::V0
        && envelope
            .domain
            .revision
            .as_ref()
            .is_some_and(|value| value != "0")
    {
        return Err(invalid_typed_data_error());
    }
    let domain_name = match revision {
        Revision::V0 => "StarkNetDomain",
        Revision::V1 => "StarknetDomain",
    };
    let serde_json::Value::Object(types) = envelope.types else {
        return Err(invalid_typed_data_error());
    };
    let (typed_data, definition) =
        decode(revision, types, envelope.primary_type, envelope.message)?;

    let mut domain =
        serde_json::to_value(&envelope.domain).map_err(|_| invalid_typed_data_error())?;
    if !definition
        .fields
        .iter()
        .any(|field| field.name == "revision")
    {
        // An undeclared revision only selects the revision. Every other
        // domain value must be declared, or encode_struct rejects it, so the
        // signature covers everything a wallet would display.
        domain
            .as_object_mut()
            .ok_or_else(invalid_typed_data_error)?
            .remove("revision");
    }
    let domain_value: Value =
        serde_json::from_value(domain).map_err(|_| invalid_typed_data_error())?;
    let encoder = typed_data.encoder();
    let domain_type_hash = domain_type_hash(revision, domain_name, &definition);
    let domain_hash = encode_struct(encoder, domain_type_hash, &definition, &domain_value)?;
    let message_hash = if typed_data.primary_type().common().is_domain(domain_name) {
        encode_struct(encoder, domain_type_hash, &definition, typed_data.message())?
    } else {
        encode_value(encoder, typed_data.primary_type(), typed_data.message())?
    };
    let prefix =
        cairo_short_string_to_felt("StarkNet Message").map_err(|_| invalid_typed_data_error())?;
    Ok(hash_elements(
        revision,
        &[prefix, domain_hash, *account_address, message_hash],
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
