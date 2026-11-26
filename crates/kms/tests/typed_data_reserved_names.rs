//! SNIP-12 documents the pinned encoder would hash differently from
//! starknet.js: struct names that shadow built-in types, and revision 1 only
//! types on revision 0. These must be refused, never hashed (issue #275).

use krusty_kms::compute_typed_data_message_hash;
use starknet_types_core::felt::Felt;

struct Vector {
    typed_data: serde_json::Value,
}

fn vector(name: &str) -> Vector {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/snip12_typed_data_vectors.json")).unwrap();
    let typed_data = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == name)
        .unwrap_or_else(|| panic!("missing SNIP-12 vector {name}"))["typed_data"]
        .clone();
    Vector { typed_data }
}

#[test]
fn rejects_revision_0_preset_type_names() {
    // Issue #275: starknet.js hashes these from the document, not the presets.
    let domain = serde_json::json!([
        {"name": "name", "type": "felt"},
        {"name": "version", "type": "felt"},
        {"name": "chainId", "type": "felt"}
    ]);
    let pair =
        serde_json::json!([{"name": "low", "type": "felt"}, {"name": "high", "type": "felt"}]);
    let amount = serde_json::json!({"high": "0x0", "low": "0x64"});
    let document = |name: &str, field_type: &str, message: serde_json::Value| {
        serde_json::json!({
            "domain": {"chainId": "SN_MAIN", "name": "App", "version": "1"},
            "message": {"amount": message},
            "primaryType": "Msg",
            "types": {
                "StarkNetDomain": domain,
                name: pair,
                "Msg": [{"name": "amount", "type": field_type}]
            }
        })
        .to_string()
    };
    let account = Felt::from_hex_unchecked("0x1234");

    // Control: the same document with a non-preset struct name still hashes.
    assert_eq!(
        compute_typed_data_message_hash(&document("Pair", "Pair", amount.clone()), &account)
            .unwrap(),
        Felt::from_hex_unchecked(
            "0x267bf73d78c05e0b27f88159a20811f14dcd271058c510225c8d58b3ee8e4d9"
        )
    );
    for (name, field_type, message) in [
        ("u256", "u256", amount.clone()),
        ("u256", "u256*", serde_json::json!([amount])),
        ("TokenAmount", "TokenAmount", amount.clone()),
        ("NftId", "NftId", amount.clone()),
        ("Pair", "u256", amount.clone()),
        ("Pair", "u256", serde_json::json!("0x64")),
    ] {
        assert!(
            compute_typed_data_message_hash(&document(name, field_type, message), &account)
                .is_err(),
            "{name} / {field_type}"
        );
    }
}

#[test]
fn rejects_declared_reserved_type_names() {
    // starknet.js hashes a declared struct that shadows a built-in name from
    // its declaration; the pinned encoder would use the built-in instead.
    let account = Felt::from_hex_unchecked("0x1234");
    let reserved = [
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
    for revision in ["revision_0_struct", "revision_1_struct"] {
        for name in reserved {
            let mut vector = vector(revision);
            vector.typed_data["types"][name] =
                serde_json::json!([{"name": "length", "type": "felt"}]);
            assert!(
                compute_typed_data_message_hash(&vector.typed_data.to_string(), &account).is_err(),
                "{revision} / {name}"
            );
        }
    }
}

#[test]
fn rejects_revision_0_revision_1_only_references() {
    let account = Felt::from_hex_unchecked("0x1234");
    let fields = [
        (
            serde_json::json!({"name": "m", "type": "merkletree", "contains": "u256"}),
            serde_json::json!([{"low": "0x1", "high": "0x0"}]),
        ),
        (
            serde_json::json!({"name": "m", "type": "enum", "contains": "Choice"}),
            serde_json::json!({"A": ["0x1"]}),
        ),
    ];
    for (field, value) in fields {
        let mut vector = vector("revision_0_struct");
        vector.typed_data["types"]["Choice"] = serde_json::json!([{"name": "A", "type": "(felt)"}]);
        vector.typed_data["types"]["Example Message"]
            .as_array_mut()
            .unwrap()
            .push(field.clone());
        vector.typed_data["message"]["m"] = value;
        assert!(
            compute_typed_data_message_hash(&vector.typed_data.to_string(), &account).is_err(),
            "{field}"
        );
    }
    let mut vector = vector("revision_0_struct");
    vector.typed_data["primaryType"] = serde_json::json!("u256");
    assert!(compute_typed_data_message_hash(&vector.typed_data.to_string(), &account).is_err());
}

#[test]
fn rejects_type_names_the_parser_reads_differently() {
    // starknet.js 10.8.0 hashes both documents from the odd declarations:
    // revision 0 `Pair*` gives 0x3d501987f059d01b85b36d409c9fc88566dc736909ca940ff0eb4c5f61fee18
    // and revision 1 ` felt` gives 0x4d27b067e7341ece1c04689df1552e8c65d79e8996c0df4ece9027475492e17.
    // The pinned parser reads `Pair*` as an array and trims ` felt`.
    let documents = [
        r#"{"domain":{"chainId":"SN_MAIN","name":"App","version":"1"},"primaryType":"Msg","types":{"StarkNetDomain":[{"name":"name","type":"felt"},{"name":"version","type":"felt"},{"name":"chainId","type":"felt"}],"Pair":[{"name":"low","type":"felt"},{"name":"high","type":"felt"}],"Pair*":[{"name":"length","type":"felt"}],"Msg":[{"name":"p","type":"Pair*"}]},"message":{"p":[{"high":"0x0","low":"0x64"},{"high":"0x0","low":"0x64"}]}}"#,
        r#"{"domain":{"chainId":"SN_MAIN","name":"App","version":"1","revision":"1"},"primaryType":"Msg","types":{"StarknetDomain":[{"name":"name","type":"shortstring"},{"name":"version","type":"shortstring"},{"name":"chainId","type":"shortstring"},{"name":"revision","type":"shortstring"}]," felt":[{"name":"length","type":"felt"}],"E":[{"name":"V","type":"(felt, felt)"}],"Msg":[{"name":"e","type":"enum","contains":"E"}]},"message":{"e":{"V":["0x1","0x22"]}}}"#,
    ];
    let account = Felt::from_hex_unchecked("0x1234");
    for document in documents {
        assert!(
            compute_typed_data_message_hash(document, &account).is_err(),
            "{document}"
        );
    }
    let mut vector = vector("revision_1_struct");
    for name in ["Pair(", "a,b", "Foo "] {
        vector.typed_data["types"][name] = serde_json::json!([{"name": "x", "type": "felt"}]);
        assert!(
            compute_typed_data_message_hash(&vector.typed_data.to_string(), &account).is_err(),
            "{name}"
        );
        vector.typed_data["types"]
            .as_object_mut()
            .unwrap()
            .remove(name);
    }
}

#[test]
fn rejects_names_and_enums_hashed_differently() {
    // starknet.js 10.8.0 hashes each of these, to (in order)
    // 0x5fa61a9bef75bc943abb4cce8e1418ea860a787d7da899dc23637f3f2556c11 (revision 1 escaping),
    // 0x5d468ccc17d702cbe2e46023d7ed4f1def1cf1ef0f785acbf548fb74d5ed841 (sort above U+FFFF) and
    // 0x48fb194def3d6be5256cfa4732bd804e6104c890bd2ea48e8040a62048d6d45 (revision 0 enum).
    let documents = [
        r#"{"domain":{"chainId":"SN_MAIN","name":"App","version":"1","revision":"1"},"primaryType":"Msg","types":{"StarknetDomain":[{"name":"name","type":"shortstring"},{"name":"version","type":"shortstring"},{"name":"chainId","type":"shortstring"},{"name":"revision","type":"shortstring"}],"Msg":[{"name":"a\"b","type":"felt"}]},"message":{"a\"b":"0x1"}}"#,
        r#"{"domain":{"chainId":"SN_MAIN","name":"App","version":"1","revision":"1"},"primaryType":"Msg","types":{"StarknetDomain":[{"name":"name","type":"shortstring"},{"name":"version","type":"shortstring"},{"name":"chainId","type":"shortstring"},{"name":"revision","type":"shortstring"}],"｡":[{"name":"a","type":"felt"}],"😀":[{"name":"a","type":"felt"}],"Msg":[{"name":"x","type":"｡"},{"name":"y","type":"😀"}]},"message":{"x":{"a":"0x1"},"y":{"a":"0x2"}}}"#,
        r#"{"domain":{"chainId":"SN_MAIN","name":"App","version":"1"},"primaryType":"E","types":{"StarkNetDomain":[{"name":"name","type":"felt"},{"name":"version","type":"felt"},{"name":"chainId","type":"felt"}],"E":[{"name":"V","type":"(felt)"}]},"message":{"V":["0x1"]}}"#,
    ];
    let account = Felt::from_hex_unchecked("0x1234");
    for document in documents {
        assert!(
            compute_typed_data_message_hash(document, &account).is_err(),
            "{document}"
        );
    }
    for name in ["a\\b", "tab\there", "V\u{1F600}"] {
        let mut vector = vector("revision_1_struct");
        vector.typed_data["types"]["Example Message"][0]["name"] = serde_json::json!(name);
        assert!(
            compute_typed_data_message_hash(&vector.typed_data.to_string(), &account).is_err(),
            "{name}"
        );
    }
}

#[test]
fn rejects_padded_enum_variant_types() {
    // starknet.js 10.8.0 keeps the spaces in the type signature, giving
    // 0x537994f152b7093f4f2908147e94e0305b3d3fe23e272bf7f1287265e3cb702 and
    // 0x2a580321f757c97dea5358f9e78c45121dc13e4e219baa5f039045aa1f38db5,
    // even though the message selects the unpadded variant.
    let account = Felt::from_hex_unchecked("0x1234");
    for document in [
        r#"{"domain":{"chainId":"SN_MAIN","name":"App","version":"1","revision":"1"},"primaryType":"Msg","types":{"StarknetDomain":[{"name":"name","type":"shortstring"},{"name":"version","type":"shortstring"},{"name":"chainId","type":"shortstring"},{"name":"revision","type":"shortstring"}],"E":[{"name":"A","type":"(felt)"},{"name":"B","type":"(felt, felt)"}],"Msg":[{"name":"e","type":"enum","contains":"E"}]},"message":{"e":{"A":["0x1"]}}}"#,
        r#"{"domain":{"chainId":"SN_MAIN","name":"App","version":"1","revision":"1"},"primaryType":"Msg","types":{"StarknetDomain":[{"name":"name","type":"shortstring"},{"name":"version","type":"shortstring"},{"name":"chainId","type":"shortstring"},{"name":"revision","type":"shortstring"}],"Foo":[{"name":"a","type":"felt"}],"E":[{"name":"A","type":"(felt)"},{"name":"B","type":"( Foo)"}],"Msg":[{"name":"e","type":"enum","contains":"E"}]},"message":{"e":{"A":["0x1"]}}}"#,
    ] {
        assert!(
            compute_typed_data_message_hash(document, &account).is_err(),
            "{document}"
        );
    }
    // Control: the unpadded spelling hashes as in starknet.js.
    assert_eq!(
        compute_typed_data_message_hash(r#"{"domain":{"chainId":"SN_MAIN","name":"App","version":"1","revision":"1"},"primaryType":"Msg","types":{"StarknetDomain":[{"name":"name","type":"shortstring"},{"name":"version","type":"shortstring"},{"name":"chainId","type":"shortstring"},{"name":"revision","type":"shortstring"}],"E":[{"name":"A","type":"(felt)"},{"name":"B","type":"(felt,felt)"}],"Msg":[{"name":"e","type":"enum","contains":"E"}]},"message":{"e":{"A":["0x1"]}}}"#, &account).unwrap(),
        Felt::from_hex_unchecked(
            "0x22c6758c9bc7fbf0de8d117faf68518814b28a52a7522ca4919fdaaed988f91"
        )
    );
}
