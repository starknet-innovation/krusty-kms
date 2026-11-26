//! Domain-type shapes the SNIP-12 compatibility layer must reject, or may
//! accept only with the digest it would have without them. These pin the
//! fail-closed behavior around starknet.js-compatible domain hashing.

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

fn v1_document() -> Value {
    json!({
        "types": {
            "StarknetDomain": v1_domain_type(),
            "Msg": [{"name": "a", "type": "felt"}]
        },
        "primaryType": "Msg",
        "domain": {"name": "Example", "version": "1", "chainId": "SN_MAIN", "revision": "1"},
        "message": {"a": "0x1"}
    })
}

#[test]
fn unused_legacy_domain_type_is_ignored_but_a_reference_to_it_is_rejected() {
    let mut document = v1_document();
    let control = hash(&document).expect("control document must hash");

    document["types"]["StarkNetDomain"] = v0_domain_type(false);
    assert_eq!(hash(&document).unwrap(), control);

    document["types"]["Msg"] = json!([{"name": "d", "type": "StarkNetDomain"}]);
    document["message"] = json!({"d": {"name": "Example", "version": "1", "chainId": "SN_MAIN"}});
    assert!(hash(&document).is_err());
}

#[test]
fn unused_empty_struct_is_ignored_but_a_reference_to_it_is_rejected() {
    let mut document = v1_document();
    let control = hash(&document).expect("control document must hash");

    document["types"]["Unused"] = json!([]);
    assert_eq!(hash(&document).unwrap(), control);

    document["types"]["Msg"] = json!([{"name": "u", "type": "Unused"}]);
    document["message"] = json!({"u": {}});
    assert!(hash(&document).is_err());
}

#[test]
fn domain_values_the_domain_type_does_not_declare_are_rejected() {
    // Only an undeclared revision is tolerated, because it selects the
    // revision. Any other undeclared value would be displayed but unsigned.
    for field in ["name", "version", "chainId"] {
        let mut document = v1_document();
        let fields = document["types"]["StarknetDomain"].as_array_mut().unwrap();
        fields.retain(|f| f["name"] != field);
        assert!(hash(&document).is_err(), "{field}");
    }
}

#[test]
fn declared_domain_fields_without_values_are_rejected() {
    for field in ["name", "version", "chainId"] {
        let mut document = v1_document();
        document["domain"].as_object_mut().unwrap().remove(field);
        assert!(hash(&document).is_err(), "{field}");
    }
}

#[test]
fn unsupported_domain_type_declarations_are_rejected() {
    let declarations = [
        json!([]),
        json!([{"name": "name", "type": "shortstring"}, {"name": "name", "type": "shortstring"}]),
        json!([{"name": "verifyingContract", "type": "felt"}]),
        json!([{"name": "name", "type": "string"}]),
        json!([{"name": "name", "type": "Msg"}]),
        json!([{"name": "Variant", "type": "enum", "contains": "Msg"}]),
    ];
    for declaration in declarations {
        let mut document = v1_document();
        document["types"]["StarknetDomain"] = declaration.clone();
        document["domain"] = json!({"name": "Example", "revision": "1"});
        assert!(hash(&document).is_err(), "{declaration}");
    }

    // Revision 0 has no shortstring type.
    let mut document = json!({
        "types": {
            "StarkNetDomain": v0_domain_type(false),
            "Msg": [{"name": "a", "type": "felt"}]
        },
        "primaryType": "Msg",
        "domain": {"name": "Example", "version": "1", "chainId": "SN_MAIN"},
        "message": {"a": "0x1"}
    });
    hash(&document).expect("control document must hash");
    document["types"]["StarkNetDomain"][0]["type"] = json!("shortstring");
    assert!(hash(&document).is_err());
}

#[test]
fn domain_type_for_the_selected_revision_is_required() {
    let mut document = v1_document();
    let domain_type = document["types"]
        .as_object_mut()
        .unwrap()
        .remove("StarknetDomain")
        .unwrap();
    document["types"]["StarkNetDomain"] = domain_type;
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

#[test]
fn built_in_and_preset_type_names_cannot_be_declared() {
    // starknet.js would let these shadow the built-in type, or reject them;
    // the pinned decoder would hash the built-in type instead.
    for name in [
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
    ] {
        for definition in [json!([]), json!([{"name": "x", "type": "bool"}])] {
            let mut document = v1_document();
            hash(&document).expect("control document must hash");
            document["types"][name] = definition.clone();
            assert!(hash(&document).is_err(), "{name}: {definition}");
        }
    }
}

#[test]
fn numeric_revision_0_is_rejected() {
    for with_revision in [false, true] {
        let mut document = json!({
            "types": {
                "StarkNetDomain": v0_domain_type(with_revision),
                "Msg": [{"name": "a", "type": "felt"}]
            },
            "primaryType": "Msg",
            "domain": {"name": "Example", "version": "1", "chainId": "SN_MAIN", "revision": "0"},
            "message": {"a": "0x1"}
        });
        hash(&document).expect("control document must hash");
        document["domain"]["revision"] = json!(0);
        assert!(hash(&document).is_err(), "with_revision={with_revision}");
    }
}

#[test]
fn explicit_null_domain_values_are_rejected() {
    for field in ["name", "version", "chainId"] {
        let mut document = v1_document();
        let fields = document["types"]["StarknetDomain"].as_array_mut().unwrap();
        fields.retain(|f| f["name"] != field);
        document["domain"].as_object_mut().unwrap().remove(field);
        hash(&document).expect("control document must hash");
        document["domain"][field] = Value::Null;
        assert!(hash(&document).is_err(), "{field}");
    }
}

#[test]
fn domain_type_referenced_by_a_message_field_is_rejected() {
    // The decoder sees only the canonical domain type, so a field of that type
    // must never hash: it would differ from starknet.js for this declaration.
    let reordered = json!([
        {"name": "chainId", "type": "shortstring"},
        {"name": "name", "type": "shortstring"},
        {"name": "version", "type": "shortstring"},
        {"name": "revision", "type": "shortstring"}
    ]);
    let domain_value =
        json!({"name": "Example", "version": "1", "chainId": "SN_MAIN", "revision": "1"});

    // Each shape hashes with the same struct under another name, so only the
    // domain reference is refused.
    for (name, refusal) in [("Dom", false), ("StarknetDomain", true)] {
        let cases = [
            (
                json!([{"name": "d", "type": name}]),
                json!({"d": domain_value}),
            ),
            (
                json!([{"name": "d", "type": format!("{name}*")}]),
                json!({"d": [domain_value]}),
            ),
            (
                json!([{"name": "e", "type": "enum", "contains": "E"}]),
                json!({"e": {"B": ["0x1", domain_value]}}),
            ),
        ];
        for (msg_type, message) in cases {
            let mut document = v1_document();
            document["types"]["StarknetDomain"] = reordered.clone();
            document["types"]["Dom"] = reordered.clone();
            document["types"]["E"] = json!([{"name": "B", "type": format!("(felt,{name})")}]);
            document["types"]["Msg"] = msg_type;
            document["message"] = message;
            assert_eq!(hash(&document).is_err(), refusal, "{name}: {document}");
        }
    }

    // A domain primary type is hashed from its declared type (starknet.js
    // 10.8.0 digest).
    let mut document = v1_document();
    document["types"]["StarknetDomain"] = reordered;
    document["primaryType"] = json!("StarknetDomain");
    document["message"] = domain_value;
    assert_eq!(
        hash(&document).unwrap(),
        Felt::from_hex_unchecked(
            "0x6dedea56066699aa9cb3b8ba1af7b096732fe846f32b2cb89fb28e80c95e5fa"
        )
    );
}
