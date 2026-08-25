//! SNIP-12 typed-data message hashing.
//!
//! Parsing and encoding are delegated to the locked `starknet-rust-core`
//! implementation so accepted documents match the Starknet ecosystem for
//! both revision 0 and revision 1.

use krusty_kms_common::{KmsError, Result};
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use starknet_rust_core::types::TypedData as StarknetTypedData;
use starknet_types_core::felt::Felt;
use std::{collections::HashSet, fmt};

/// Maximum accepted typed-data JSON size.
///
/// Typed data is normally small and may arrive through FFI or WASM. Callers
/// have already allocated the input string by this point; this limit bounds
/// JSON parsing work and the amplified in-memory typed-data tree.
const MAX_TYPED_DATA_JSON_BYTES: usize = 256 * 1024;

/// Do not surface reference-encoder details because they can contain
/// attacker-controlled field or type names that callers may log.
const INVALID_TYPED_DATA_ERROR: &str = "typed data is not valid canonical SNIP-12";

/// Validate the signed envelope before handing its fields to the reference
/// encoder. `TypedData` itself intentionally ignores unknown top-level keys,
/// which is unsafe for signing UIs that display the complete JSON document.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalTypedDataEnvelope {
    types: serde_json::Value,
    domain: CanonicalTypedDataDomain,
    #[serde(rename = "primaryType")]
    primary_type: serde_json::Value,
    message: serde_json::Value,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalTypedDataDomain {
    name: serde_json::Value,
    version: serde_json::Value,
    #[serde(rename = "chainId")]
    chain_id: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revision: Option<serde_json::Value>,
}

fn invalid_typed_data_error() -> KmsError {
    KmsError::SerializationError(INVALID_TYPED_DATA_ERROR.to_owned())
}

struct RejectDuplicateKeys;

impl<'de> DeserializeSeed<'de> for RejectDuplicateKeys {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for RejectDuplicateKeys {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(RejectDuplicateKeys)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(RejectDuplicateKeys)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_none<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }
}

fn reject_duplicate_json_keys(json: &str) -> serde_json::Result<()> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    RejectDuplicateKeys.deserialize(&mut deserializer)?;
    deserializer.end()
}

/// Compute the canonical SNIP-12 message hash for an account.
///
/// The document's domain and type definitions select SNIP-12 revision 0 or 1.
/// Unsupported, inconsistent, or noncanonical documents are rejected by the
/// reference encoder rather than being partially interpreted.
pub fn compute_typed_data_message_hash(
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
    let typed_data: StarknetTypedData = serde_json::from_value(
        serde_json::to_value(envelope).map_err(|_| invalid_typed_data_error())?,
    )
    .map_err(|_| invalid_typed_data_error())?;
    typed_data
        .message_hash(*account_address)
        .map_err(|_| invalid_typed_data_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Fixture {
        vectors: Vec<Vector>,
    }

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        account_address: String,
        expected_hash: String,
        typed_data: serde_json::Value,
    }

    fn vector(name: &str) -> Vector {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../tests/fixtures/snip12_typed_data_vectors.json"
        ))
        .unwrap();

        fixture
            .vectors
            .into_iter()
            .find(|vector| vector.name == name)
            .unwrap_or_else(|| panic!("missing SNIP-12 vector {name}"))
    }

    fn assert_vector(name: &str) {
        let vector = vector(name);
        let account = Felt::from_hex(&vector.account_address).unwrap();
        let hash = compute_typed_data_message_hash(&vector.typed_data.to_string(), &account)
            .expect("fixture must hash");

        assert_eq!(hash, Felt::from_hex(&vector.expected_hash).unwrap());
    }

    #[test]
    fn hashes_revision_0_with_pedersen() {
        assert_vector("revision_0_struct");
    }

    #[test]
    fn hashes_revision_1_strings_with_poseidon() {
        assert_vector("revision_1_struct");
    }

    #[test]
    fn hashes_revision_1_preset_types() {
        assert_vector("revision_1_preset_types");
    }

    #[test]
    fn rejects_extra_message_fields() {
        let mut vector = vector("revision_1_struct");
        vector.typed_data["message"]["Undeclared"] = serde_json::json!("misleading display text");

        assert!(compute_typed_data_message_hash(
            &vector.typed_data.to_string(),
            &Felt::from_hex_unchecked("0x1234")
        )
        .is_err());
    }

    #[test]
    fn rejects_extra_nested_message_fields() {
        let mut vector = vector("revision_1_struct");
        vector.typed_data["message"]["Some Object"]["Undeclared"] =
            serde_json::json!("misleading display text");

        assert!(compute_typed_data_message_hash(
            &vector.typed_data.to_string(),
            &Felt::from_hex_unchecked("0x1234")
        )
        .is_err());
    }

    #[test]
    fn rejects_extra_envelope_fields() {
        let mut vector = vector("revision_1_struct");
        vector.typed_data["warning"] = serde_json::json!("you are sending 100 ETH");

        let error = compute_typed_data_message_hash(
            &vector.typed_data.to_string(),
            &Felt::from_hex_unchecked("0x1234"),
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("Serialization error: {INVALID_TYPED_DATA_ERROR}")
        );
        assert!(!error.to_string().contains("warning"));
    }

    #[test]
    fn rejects_extra_domain_fields() {
        let mut vector = vector("revision_1_struct");
        vector.typed_data["domain"]["warning"] =
            serde_json::json!("this text is not covered by the signature");

        let error = compute_typed_data_message_hash(
            &vector.typed_data.to_string(),
            &Felt::from_hex_unchecked("0x1234"),
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("Serialization error: {INVALID_TYPED_DATA_ERROR}")
        );
        assert!(!error.to_string().contains("warning"));
    }

    #[test]
    fn rejects_duplicate_envelope_fields() {
        let vector = vector("revision_1_struct");
        let canonical = vector.typed_data.to_string();
        let duplicate = format!(
            "{{\"message\":{},{}",
            vector.typed_data["message"],
            &canonical[1..]
        );

        assert!(
            compute_typed_data_message_hash(&duplicate, &Felt::from_hex_unchecked("0x1234"))
                .is_err()
        );
    }

    #[test]
    fn rejects_duplicate_keys_recursively() {
        let canonical = vector("revision_1_struct").typed_data.to_string();
        let duplicates = [
            ("\"name\":\"Name\"", "\"name\":\"Name\",\"name\":\"Name\""),
            (
                "\"revision\":\"1\"",
                "\"revision\":\"1\",\"revision\":\"1\"",
            ),
            (
                "\"Name\":\"some name\"",
                "\"Name\":\"some name\",\"Name\":\"some name\"",
            ),
            (
                "\"Some Selector\":\"transfer\"",
                "\"Some Selector\":\"transfer\",\"Some Selector\":\"transfer\"",
            ),
        ];

        for (needle, replacement) in duplicates {
            assert!(canonical.contains(needle));
            let duplicate = canonical.replacen(needle, replacement, 1);
            assert!(compute_typed_data_message_hash(
                &duplicate,
                &Felt::from_hex_unchecked("0x1234")
            )
            .is_err());
        }
    }

    #[test]
    fn rejects_missing_message_fields() {
        let mut vector = vector("revision_1_struct");
        vector.typed_data["message"]
            .as_object_mut()
            .unwrap()
            .remove("Name");

        assert!(compute_typed_data_message_hash(
            &vector.typed_data.to_string(),
            &Felt::from_hex_unchecked("0x1234")
        )
        .is_err());
    }

    #[test]
    fn rejects_inconsistent_revisions() {
        let mut vector = vector("revision_0_struct");
        vector.typed_data["domain"]["revision"] = serde_json::json!("1");

        let error = compute_typed_data_message_hash(
            &vector.typed_data.to_string(),
            &Felt::from_hex_unchecked("0x1234"),
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("Serialization error: {INVALID_TYPED_DATA_ERROR}")
        );
        assert!(!error.to_string().contains("revision"));
    }

    #[test]
    fn encoder_errors_do_not_echo_attacker_controlled_fields() {
        let mut vector = vector("revision_1_struct");
        vector.typed_data["message"]["TOP_SECRET_FIELD_NAME"] = serde_json::json!("secret");

        let error = compute_typed_data_message_hash(
            &vector.typed_data.to_string(),
            &Felt::from_hex_unchecked("0x1234"),
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("Serialization error: {INVALID_TYPED_DATA_ERROR}")
        );
        assert!(!error.to_string().contains("TOP_SECRET_FIELD_NAME"));
    }

    #[test]
    fn accepts_document_at_exact_size_limit() {
        let vector = vector("revision_1_struct");
        let mut json = vector.typed_data.to_string();
        json.extend(std::iter::repeat_n(
            ' ',
            MAX_TYPED_DATA_JSON_BYTES - json.len(),
        ));

        assert_eq!(json.len(), MAX_TYPED_DATA_JSON_BYTES);
        assert!(
            compute_typed_data_message_hash(&json, &Felt::from_hex_unchecked("0x1234")).is_ok()
        );
    }

    #[test]
    fn rejects_oversized_documents_before_parsing() {
        // Whitespace is invalid as a complete JSON document, so this assertion
        // distinguishes the byte-limit check from a later parser error.
        let oversized = " ".repeat(MAX_TYPED_DATA_JSON_BYTES + 1);
        let error = compute_typed_data_message_hash(&oversized, &Felt::ZERO).unwrap_err();

        assert!(error.to_string().contains("exceeds"));
    }
}
