//! `selector_from_name` against selectors produced by starknet.js.
//!
//! `cross-tests/src/verify-selector-vectors.ts` re-verifies the same fixture
//! with starknet.js in CI, so the two implementations cannot drift apart.

use krusty_kms::selector_from_name;
use serde::Deserialize;
use starknet_types_core::felt::Felt;

#[derive(Deserialize)]
struct Fixture {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    selector: String,
}

#[test]
fn selector_from_name_matches_starknet_js() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/selector_vectors.json")).unwrap();
    // The rows where starknet.js and starknet-rs disagree must stay pinned.
    for required in ["__default__", "__l1_default__", "tränsfer"] {
        assert!(fixture.vectors.iter().any(|v| v.name == required));
    }

    for vector in fixture.vectors {
        assert_eq!(
            selector_from_name(&vector.name),
            Felt::from_hex(&vector.selector).unwrap(),
            "selector mismatch for {:?}",
            vector.name
        );
    }
}
