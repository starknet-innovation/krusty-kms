//! Domain-type shapes the pinned SNIP-12 decoder rejects before the
//! starknet.js compatibility encoder runs. These pin fail-closed behavior
//! the compatibility layer relies on.

use krusty_kms::compute_typed_data_message_hash;
use serde_json::{json, Value};
use starknet_types_core::felt::Felt;

fn hash(document: &Value) -> krusty_kms_common::Result<Felt> {
    compute_typed_data_message_hash(&document.to_string(), &Felt::from(0x1234_u32))
}

fn v1_domain_type() -> Value {
    json!([
        {"name": "name", "type": "shortstring"},
        {"name": "version", "type": "shortstring"},
        {"name": "chainId", "type": "shortstring"},
        {"name": "revision", "type": "shortstring"}
    ])
}

fn v0_domain_type(with_revision: bool) -> Value {
    let mut fields = vec![
        json!({"name": "name", "type": "felt"}),
        json!({"name": "version", "type": "felt"}),
        json!({"name": "chainId", "type": "felt"}),
    ];
    if with_revision {
        fields.push(json!({"name": "revision", "type": "felt"}));
    }
    Value::Array(fields)
}

#[test]
fn revision_1_document_with_both_domain_types_is_rejected() {
    let mut document = json!({
        "types": {
            "StarknetDomain": v1_domain_type(),
            "Msg": [{"name": "a", "type": "felt"}]
        },
        "primaryType": "Msg",
        "domain": {"name": "Example", "version": "1", "chainId": "SN_MAIN", "revision": "1"},
        "message": {"a": "0x1"}
    });
    hash(&document).expect("control document must hash");

    document["types"]["StarkNetDomain"] = v0_domain_type(false);
    assert!(hash(&document).is_err());
}

#[test]
fn legacy_domain_referenced_by_a_message_type_is_rejected() {
    for with_revision in [false, true] {
        let domain = if with_revision {
            json!({"name": "Example", "version": "1", "chainId": "SN_MAIN", "revision": "0"})
        } else {
            json!({"name": "Example", "version": "1", "chainId": "SN_MAIN"})
        };
        let mut document = json!({
            "types": {
                "StarkNetDomain": v0_domain_type(with_revision),
                "Msg": [{"name": "a", "type": "felt"}]
            },
            "primaryType": "Msg",
            "domain": domain,
            "message": {"a": "0x1"}
        });
        hash(&document).expect("control document must hash");

        document["types"]["Msg"] = json!([{"name": "d", "type": "StarkNetDomain"}]);
        document["message"] = json!({"d": domain});
        assert!(hash(&document).is_err(), "with_revision={with_revision}");

        document["types"]["Msg"] = json!([{"name": "d", "type": "StarkNetDomain*"}]);
        document["message"] = json!({"d": [domain]});
        assert!(
            hash(&document).is_err(),
            "array, with_revision={with_revision}"
        );
    }
}
