//! Transaction hash parity tests.
//!
//! These tests verify that the KMS hash implementation produces stable,
//! pinned hash values that can be independently reproduced in starknet.js
//! (or any other Starknet SDK).

use krusty_kms::tx_hash::{DaMode, ResourceBounds};
use serde::Deserialize;
use starknet_types_core::felt::Felt;

// ---------------------------------------------------------------------------
// JSON fixture schema
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Fixture {
    vectors: Vectors,
}

#[derive(Deserialize)]
struct Vectors {
    invoke_v1: Vec<InvokeV1>,
    invoke_v3: Vec<InvokeV3>,
    deploy_account_v1: Vec<DeployAccountV1>,
    deploy_account_v3: Vec<DeployAccountV3>,
    declare_v2: Vec<DeclareV2>,
    declare_v3: Vec<DeclareV3>,
}

#[derive(Deserialize)]
struct InvokeV1 {
    name: String,
    sender_address: String,
    calldata: Vec<String>,
    max_fee: String,
    chain_id: String,
    nonce: String,
    expected_hash: String,
}

#[derive(Deserialize)]
struct InvokeV3 {
    name: String,
    sender_address: String,
    calldata: Vec<String>,
    chain_id: String,
    nonce: String,
    tip: String,
    l1_gas: GasBounds,
    l2_gas: GasBounds,
    l1_data_gas: GasBounds,
    paymaster_data: Vec<String>,
    nonce_da_mode: u8,
    fee_da_mode: u8,
    account_deployment_data: Vec<String>,
    proof_facts: Option<Vec<String>>,
    expected_hash: String,
}

#[derive(Deserialize)]
struct DeployAccountV1 {
    name: String,
    contract_address: String,
    class_hash: String,
    constructor_calldata: Vec<String>,
    salt: String,
    max_fee: String,
    chain_id: String,
    nonce: String,
    expected_hash: String,
}

#[derive(Deserialize)]
struct DeployAccountV3 {
    name: String,
    contract_address: String,
    class_hash: String,
    constructor_calldata: Vec<String>,
    salt: String,
    chain_id: String,
    nonce: String,
    tip: String,
    l1_gas: GasBounds,
    l2_gas: GasBounds,
    l1_data_gas: GasBounds,
    paymaster_data: Vec<String>,
    nonce_da_mode: u8,
    fee_da_mode: u8,
    expected_hash: String,
}

#[derive(Deserialize)]
struct DeclareV2 {
    name: String,
    sender_address: String,
    class_hash: String,
    max_fee: String,
    chain_id: String,
    nonce: String,
    compiled_class_hash: String,
    expected_hash: String,
}

#[derive(Deserialize)]
struct DeclareV3 {
    name: String,
    sender_address: String,
    class_hash: String,
    compiled_class_hash: String,
    chain_id: String,
    nonce: String,
    tip: String,
    l1_gas: GasBounds,
    l2_gas: GasBounds,
    l1_data_gas: GasBounds,
    paymaster_data: Vec<String>,
    nonce_da_mode: u8,
    fee_da_mode: u8,
    account_deployment_data: Vec<String>,
    expected_hash: String,
}

#[derive(Deserialize)]
struct GasBounds {
    max_amount: String,
    max_price_per_unit: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn felt(hex: &str) -> Felt {
    Felt::from_hex(hex).unwrap_or_else(|e| panic!("bad hex `{hex}`: {e}"))
}

fn felts(hexes: &[String]) -> Vec<Felt> {
    hexes.iter().map(|h| felt(h)).collect()
}

fn da_mode(v: u8) -> DaMode {
    match v {
        0 => DaMode::L1,
        1 => DaMode::L2,
        _ => panic!("invalid DA mode: {v}"),
    }
}

fn resource_bounds(gb: &GasBounds) -> ResourceBounds {
    ResourceBounds {
        max_amount: u64::from_str_radix(gb.max_amount.trim_start_matches("0x"), 16)
            .expect("bad max_amount"),
        max_price_per_unit: u128::from_str_radix(
            gb.max_price_per_unit.trim_start_matches("0x"),
            16,
        )
        .expect("bad max_price_per_unit"),
    }
}

fn tip(hex: &str) -> u64 {
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).expect("bad tip")
}

fn load_fixture() -> Fixture {
    let json = include_str!("fixtures/tx_hash_parity_vectors.json");
    serde_json::from_str(json).expect("bad fixture JSON")
}

// ---------------------------------------------------------------------------
// Generator (run with --ignored --nocapture to print expected hashes)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn generate_tx_hash_parity_vectors() {
    let fixture = load_fixture();

    println!("=== Invoke V1 ===");
    for v in &fixture.vectors.invoke_v1 {
        let h = krusty_kms::compute_invoke_v1_hash(
            &felt(&v.sender_address),
            &felts(&v.calldata),
            &felt(&v.max_fee),
            &felt(&v.chain_id),
            &felt(&v.nonce),
        );
        println!("{}: {:#066x}", v.name, h);
    }

    println!("\n=== Invoke V3 ===");
    for v in &fixture.vectors.invoke_v3 {
        let l1 = resource_bounds(&v.l1_gas);
        let l2 = resource_bounds(&v.l2_gas);
        let l1d = resource_bounds(&v.l1_data_gas);
        let h = match &v.proof_facts {
            Some(proof_facts) => krusty_kms::compute_invoke_v3_hash_with_proof_facts(
                &felt(&v.sender_address),
                &felts(&v.calldata),
                &felt(&v.chain_id),
                &felt(&v.nonce),
                &felts(&v.account_deployment_data),
                tip(&v.tip),
                &l1,
                &l2,
                &l1d,
                &felts(&v.paymaster_data),
                da_mode(v.nonce_da_mode),
                da_mode(v.fee_da_mode),
                &felts(proof_facts),
            ),
            None => krusty_kms::compute_invoke_v3_hash(
                &felt(&v.sender_address),
                &felts(&v.calldata),
                &felt(&v.chain_id),
                &felt(&v.nonce),
                &felts(&v.account_deployment_data),
                tip(&v.tip),
                &l1,
                &l2,
                &l1d,
                &felts(&v.paymaster_data),
                da_mode(v.nonce_da_mode),
                da_mode(v.fee_da_mode),
            ),
        };
        println!("{}: {:#066x}", v.name, h);
    }

    println!("\n=== Deploy Account V1 ===");
    for v in &fixture.vectors.deploy_account_v1 {
        let h = krusty_kms::compute_deploy_account_v1_hash(
            &felt(&v.contract_address),
            &felt(&v.class_hash),
            &felts(&v.constructor_calldata),
            &felt(&v.salt),
            &felt(&v.max_fee),
            &felt(&v.chain_id),
            &felt(&v.nonce),
        );
        println!("{}: {:#066x}", v.name, h);
    }

    println!("\n=== Deploy Account V3 ===");
    for v in &fixture.vectors.deploy_account_v3 {
        let l1 = resource_bounds(&v.l1_gas);
        let l2 = resource_bounds(&v.l2_gas);
        let l1d = resource_bounds(&v.l1_data_gas);
        let h = krusty_kms::compute_deploy_account_v3_hash(
            &felt(&v.contract_address),
            &felt(&v.class_hash),
            &felts(&v.constructor_calldata),
            &felt(&v.salt),
            &felt(&v.chain_id),
            &felt(&v.nonce),
            tip(&v.tip),
            &l1,
            &l2,
            &l1d,
            &felts(&v.paymaster_data),
            da_mode(v.nonce_da_mode),
            da_mode(v.fee_da_mode),
        );
        println!("{}: {:#066x}", v.name, h);
    }

    println!("\n=== Declare V2 ===");
    for v in &fixture.vectors.declare_v2 {
        let h = krusty_kms::compute_declare_v2_hash(
            &felt(&v.sender_address),
            &felt(&v.class_hash),
            &felt(&v.max_fee),
            &felt(&v.chain_id),
            &felt(&v.nonce),
            &felt(&v.compiled_class_hash),
        );
        println!("{}: {:#066x}", v.name, h);
    }

    println!("\n=== Declare V3 ===");
    for v in &fixture.vectors.declare_v3 {
        let l1 = resource_bounds(&v.l1_gas);
        let l2 = resource_bounds(&v.l2_gas);
        let l1d = resource_bounds(&v.l1_data_gas);
        let h = krusty_kms::compute_declare_v3_hash(
            &felt(&v.sender_address),
            &felt(&v.class_hash),
            &felt(&v.compiled_class_hash),
            &felt(&v.chain_id),
            &felt(&v.nonce),
            tip(&v.tip),
            &l1,
            &l2,
            &l1d,
            &felts(&v.paymaster_data),
            da_mode(v.nonce_da_mode),
            da_mode(v.fee_da_mode),
            &felts(&v.account_deployment_data),
        );
        println!("{}: {:#066x}", v.name, h);
    }
}

// ---------------------------------------------------------------------------
// Pinned-hash verification (runs in normal `cargo test`)
// ---------------------------------------------------------------------------

#[test]
fn tx_hash_parity_vectors_match() {
    let fixture = load_fixture();

    for v in &fixture.vectors.invoke_v1 {
        let computed = krusty_kms::compute_invoke_v1_hash(
            &felt(&v.sender_address),
            &felts(&v.calldata),
            &felt(&v.max_fee),
            &felt(&v.chain_id),
            &felt(&v.nonce),
        );
        assert_eq!(
            computed,
            felt(&v.expected_hash),
            "invoke_v1 `{}` mismatch",
            v.name,
        );
    }

    for v in &fixture.vectors.invoke_v3 {
        let l1 = resource_bounds(&v.l1_gas);
        let l2 = resource_bounds(&v.l2_gas);
        let l1d = resource_bounds(&v.l1_data_gas);
        let computed = match &v.proof_facts {
            Some(proof_facts) => krusty_kms::compute_invoke_v3_hash_with_proof_facts(
                &felt(&v.sender_address),
                &felts(&v.calldata),
                &felt(&v.chain_id),
                &felt(&v.nonce),
                &felts(&v.account_deployment_data),
                tip(&v.tip),
                &l1,
                &l2,
                &l1d,
                &felts(&v.paymaster_data),
                da_mode(v.nonce_da_mode),
                da_mode(v.fee_da_mode),
                &felts(proof_facts),
            ),
            None => krusty_kms::compute_invoke_v3_hash(
                &felt(&v.sender_address),
                &felts(&v.calldata),
                &felt(&v.chain_id),
                &felt(&v.nonce),
                &felts(&v.account_deployment_data),
                tip(&v.tip),
                &l1,
                &l2,
                &l1d,
                &felts(&v.paymaster_data),
                da_mode(v.nonce_da_mode),
                da_mode(v.fee_da_mode),
            ),
        };
        assert_eq!(
            computed,
            felt(&v.expected_hash),
            "invoke_v3 `{}` mismatch",
            v.name,
        );
    }

    for v in &fixture.vectors.deploy_account_v1 {
        let computed = krusty_kms::compute_deploy_account_v1_hash(
            &felt(&v.contract_address),
            &felt(&v.class_hash),
            &felts(&v.constructor_calldata),
            &felt(&v.salt),
            &felt(&v.max_fee),
            &felt(&v.chain_id),
            &felt(&v.nonce),
        );
        assert_eq!(
            computed,
            felt(&v.expected_hash),
            "deploy_account_v1 `{}` mismatch",
            v.name,
        );
    }

    for v in &fixture.vectors.deploy_account_v3 {
        let l1 = resource_bounds(&v.l1_gas);
        let l2 = resource_bounds(&v.l2_gas);
        let l1d = resource_bounds(&v.l1_data_gas);
        let computed = krusty_kms::compute_deploy_account_v3_hash(
            &felt(&v.contract_address),
            &felt(&v.class_hash),
            &felts(&v.constructor_calldata),
            &felt(&v.salt),
            &felt(&v.chain_id),
            &felt(&v.nonce),
            tip(&v.tip),
            &l1,
            &l2,
            &l1d,
            &felts(&v.paymaster_data),
            da_mode(v.nonce_da_mode),
            da_mode(v.fee_da_mode),
        );
        assert_eq!(
            computed,
            felt(&v.expected_hash),
            "deploy_account_v3 `{}` mismatch",
            v.name,
        );
    }

    for v in &fixture.vectors.declare_v2 {
        let computed = krusty_kms::compute_declare_v2_hash(
            &felt(&v.sender_address),
            &felt(&v.class_hash),
            &felt(&v.max_fee),
            &felt(&v.chain_id),
            &felt(&v.nonce),
            &felt(&v.compiled_class_hash),
        );
        assert_eq!(
            computed,
            felt(&v.expected_hash),
            "declare_v2 `{}` mismatch",
            v.name,
        );
    }

    for v in &fixture.vectors.declare_v3 {
        let l1 = resource_bounds(&v.l1_gas);
        let l2 = resource_bounds(&v.l2_gas);
        let l1d = resource_bounds(&v.l1_data_gas);
        let computed = krusty_kms::compute_declare_v3_hash(
            &felt(&v.sender_address),
            &felt(&v.class_hash),
            &felt(&v.compiled_class_hash),
            &felt(&v.chain_id),
            &felt(&v.nonce),
            tip(&v.tip),
            &l1,
            &l2,
            &l1d,
            &felts(&v.paymaster_data),
            da_mode(v.nonce_da_mode),
            da_mode(v.fee_da_mode),
            &felts(&v.account_deployment_data),
        );
        assert_eq!(
            computed,
            felt(&v.expected_hash),
            "declare_v3 `{}` mismatch",
            v.name,
        );
    }
}
