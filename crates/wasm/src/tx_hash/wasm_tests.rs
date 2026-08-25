use super::*;
use wasm_bindgen_test::*;

fn resource_bounds() -> JsValue {
    serde_wasm_bindgen::to_value(&ResourceBoundsInput {
        l1_gas: ResourceBoundInput {
            max_amount: "0x186a0".to_string(),
            max_price_per_unit: "0x5af3107a4000".to_string(),
        },
        l2_gas: ResourceBoundInput {
            max_amount: "0x0".to_string(),
            max_price_per_unit: "0x0".to_string(),
        },
        l1_data_gas: Some(ResourceBoundInput {
            max_amount: "0x0".to_string(),
            max_price_per_unit: "0x0".to_string(),
        }),
    })
    .unwrap()
}

fn compute_v3(proof_facts: Option<Vec<String>>) -> String {
    compute_invoke_transaction_hash_v3(
        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        vec!["0x1".to_string(), "0x2".to_string(), "0x3".to_string()],
        "0x534e5f5345504f4c4941",
        "0x7",
        "0x0",
        resource_bounds(),
        vec![],
        0,
        0,
        vec![],
        proof_facts,
    )
    .unwrap()
}

#[wasm_bindgen_test]
fn parse_felt_rejects_invalid_input() {
    assert!(parse_felt("not_hex").is_err());
    assert!(parse_felt("").is_err());
}

#[wasm_bindgen_test]
fn da_mode_from_u8_rejects_out_of_range() {
    assert!(da_mode_from_u8(2).is_err());
    assert!(da_mode_from_u8(255).is_err());
}

#[wasm_bindgen_test]
fn parse_tip_rejects_invalid_input() {
    assert!(parse_tip("not_a_number").is_err());
}

#[wasm_bindgen_test]
fn typed_data_binding_matches_official_vector() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../kms/tests/fixtures/snip12_typed_data_vectors.json"
    ))
    .unwrap();
    let vector = &fixture["vectors"][0];
    let account = vector["account_address"].as_str().unwrap();
    let expected = vector["expected_hash"].as_str().unwrap();

    let actual = compute_typed_data_message_hash(&vector["typed_data"].to_string(), account)
        .expect("official vector must hash through the WASM boundary");

    assert_eq!(
        parse_felt(&actual).unwrap(),
        Felt::from_hex(expected).unwrap()
    );
}

#[wasm_bindgen_test]
fn invoke_v3_empty_proof_facts_match_omitted_proof_facts() {
    assert_eq!(compute_v3(None), compute_v3(Some(vec![])));
}

#[wasm_bindgen_test]
fn invoke_v3_proof_facts_match_starknet_js_10_0_2_vector() {
    let hash = compute_v3(Some(vec![
        "0x123".to_string(),
        "0x456".to_string(),
        "0x789".to_string(),
    ]));
    assert_eq!(
        hash,
        "0x15f5114c744e730be573a540456ad0a05d5f72964143b9839c57abc5ee7b31"
    );
}
