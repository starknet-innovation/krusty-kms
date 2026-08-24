//! SNIP-12 typed-data message hashing.
//!
//! Parsing and encoding are delegated to the locked `starknet-rust-core`
//! implementation so accepted documents match the Starknet ecosystem for
//! both revision 0 and revision 1.

use krusty_kms_common::{KmsError, Result};
use starknet_rust_core::types::TypedData as StarknetTypedData;
use starknet_types_core::felt::Felt;

/// Maximum accepted typed-data JSON size.
///
/// Typed data is normally small and may arrive through FFI or WASM. Rejecting
/// oversized documents before deserialization keeps those boundaries from
/// turning a signing request into an unbounded allocation.
const MAX_TYPED_DATA_JSON_BYTES: usize = 256 * 1024;

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

    let typed_data: StarknetTypedData = serde_json::from_str(typed_data_json)?;
    typed_data
        .message_hash(*account_address)
        .map_err(|error| KmsError::SerializationError(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_V0_DATA: &str = r#"{
      "types": {
        "StarkNetDomain": [
          { "name": "name", "type": "felt" },
          { "name": "version", "type": "felt" },
          { "name": "chainId", "type": "felt" }
        ],
        "Example Message": [
          { "name": "Name", "type": "string" },
          { "name": "Some Array", "type": "u128*" },
          { "name": "Some Object", "type": "My Object" }
        ],
        "My Object": [
          { "name": "Some Selector", "type": "selector" },
          { "name": "Some Contract Address", "type": "ContractAddress" }
        ]
      },
      "primaryType": "Example Message",
      "domain": {
        "name": "Starknet Example",
        "version": "1",
        "chainId": "SN_MAIN"
      },
      "message": {
        "Name": "some name",
        "Some Array": [1, 2, 3, 4],
        "Some Object": {
          "Some Selector": "transfer",
          "Some Contract Address": "0x0123"
        }
      }
    }"#;

    const VALID_V1_DATA: &str = r#"{
      "types": {
        "StarknetDomain": [
          { "name": "name", "type": "shortstring" },
          { "name": "version", "type": "shortstring" },
          { "name": "chainId", "type": "shortstring" },
          { "name": "revision", "type": "shortstring" }
        ],
        "Example Message": [
          { "name": "Name", "type": "string" },
          { "name": "Some Array", "type": "u128*" },
          { "name": "Some Object", "type": "My Object" }
        ],
        "My Object": [
          { "name": "Some Selector", "type": "selector" },
          { "name": "Some Contract Address", "type": "ContractAddress" }
        ]
      },
      "primaryType": "Example Message",
      "domain": {
        "name": "Starknet Example",
        "version": "1",
        "chainId": "SN_MAIN",
        "revision": "1"
      },
      "message": {
        "Name": "some name",
        "Some Array": [1, 2, 3, 4],
        "Some Object": {
          "Some Selector": "transfer",
          "Some Contract Address": "0x0123"
        }
      }
    }"#;

    const VALID_V1_U256_DATA: &str = r#"{
      "types": {
        "StarknetDomain": [
          { "name": "name", "type": "shortstring" },
          { "name": "version", "type": "shortstring" },
          { "name": "chainId", "type": "shortstring" },
          { "name": "revision", "type": "shortstring" }
        ],
        "Example Message": [
          { "name": "Uint", "type": "u256" },
          { "name": "Amount", "type": "TokenAmount" },
          { "name": "Id", "type": "NftId" }
        ]
      },
      "primaryType": "Example Message",
      "domain": {
        "name": "Starknet Example",
        "version": "1",
        "chainId": "SN_MAIN",
        "revision": "1"
      },
      "message": {
        "Uint": { "low": "1234", "high": "0x5678" },
        "Amount": {
          "token_address": "0x11223344",
          "amount": { "low": 1000000, "high": 0 }
        },
        "Id": {
          "collection_address": "0x55667788",
          "token_id": { "low": "0x12345678", "high": 0 }
        }
      }
    }"#;

    #[test]
    fn hashes_revision_0_with_pedersen() {
        let hash =
            compute_typed_data_message_hash(VALID_V0_DATA, &Felt::from_hex_unchecked("0x1234"))
                .unwrap();

        assert_eq!(
            hash,
            Felt::from_hex_unchecked(
                "0x0778d68fe2baf73ee78a6711c29bad4722680984c1553a8035c8cb3feb5310c9"
            )
        );
    }

    #[test]
    fn hashes_revision_1_strings_with_poseidon() {
        let hash =
            compute_typed_data_message_hash(VALID_V1_DATA, &Felt::from_hex_unchecked("0x1234"))
                .unwrap();

        assert_eq!(
            hash,
            Felt::from_hex_unchecked(
                "0x045bca39274d2b7fdf7dc7c4ecf75f6549f614ce44359cc62ec106f4e5cc87b4"
            )
        );
    }

    #[test]
    fn hashes_revision_1_preset_types() {
        let hash = compute_typed_data_message_hash(
            VALID_V1_U256_DATA,
            &Felt::from_hex_unchecked("0x1234"),
        )
        .unwrap();

        assert_eq!(
            hash,
            Felt::from_hex_unchecked(
                "0x068b85f4061d8155c0445f7e3c6bae1e7641b88b1d3b7c034c0b4f6c30eb5049"
            )
        );
    }

    #[test]
    fn rejects_extra_message_fields() {
        let mut value: serde_json::Value = serde_json::from_str(VALID_V1_DATA).unwrap();
        value["message"]["Undeclared"] = serde_json::json!("misleading display text");

        assert!(compute_typed_data_message_hash(
            &value.to_string(),
            &Felt::from_hex_unchecked("0x1234")
        )
        .is_err());
    }

    #[test]
    fn rejects_missing_message_fields() {
        let mut value: serde_json::Value = serde_json::from_str(VALID_V1_DATA).unwrap();
        value["message"].as_object_mut().unwrap().remove("Name");

        assert!(compute_typed_data_message_hash(
            &value.to_string(),
            &Felt::from_hex_unchecked("0x1234")
        )
        .is_err());
    }

    #[test]
    fn rejects_inconsistent_revisions() {
        let mut value: serde_json::Value = serde_json::from_str(VALID_V0_DATA).unwrap();
        value["domain"]["revision"] = serde_json::json!("1");

        assert!(compute_typed_data_message_hash(
            &value.to_string(),
            &Felt::from_hex_unchecked("0x1234")
        )
        .is_err());
    }

    #[test]
    fn rejects_oversized_documents_before_parsing() {
        let oversized = " ".repeat(MAX_TYPED_DATA_JSON_BYTES + 1);
        let error = compute_typed_data_message_hash(&oversized, &Felt::ZERO).unwrap_err();

        assert!(error.to_string().contains("exceeds"));
    }
}
