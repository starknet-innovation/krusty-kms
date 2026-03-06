//! Cross-SDK compatibility test vectors.
//!
//! Generates proof data that can be verified by the TypeScript tongo-sdk.
//! Run with: cargo test -p krusty-kms-sdk --test cross_compat -- --ignored --nocapture

use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_crypto::StarkCurve;
use krusty_kms_sdk::operations::{
    fund, ragequit, rollover, FundParams, RagequitParams, RolloverParams,
};
use krusty_kms_sdk::TongoAccount;
use serde_json::{json, Value};
use starknet_types_core::felt::Felt;
use std::fs;

fn point_to_json(point: &starknet_types_core::curve::ProjectivePoint) -> Value {
    let affine = point.to_affine().expect("point at infinity");
    json!({
        "x": format!("{:#x}", affine.x()),
        "y": format!("{:#x}", affine.y()),
    })
}

fn felt_to_hex(f: &Felt) -> String {
    format!("{:#x}", f)
}

struct FundCase {
    name: &'static str,
    description: &'static str,
    private_key: &'static str,
    amount: u128,
    initial_balance: u128,
    nonce: &'static str,
    chain_id: &'static str,
    tongo_address: &'static str,
    sender_address: &'static str,
    fee_to_sender: u128,
}

struct RolloverCase {
    name: &'static str,
    description: &'static str,
    private_key: &'static str,
    nonce: &'static str,
    chain_id: &'static str,
    tongo_address: &'static str,
    sender_address: &'static str,
}

struct RagequitCase {
    name: &'static str,
    description: &'static str,
    private_key: &'static str,
    amount: u128,
    send_to: &'static str,
    nonce: &'static str,
    chain_id: &'static str,
    tongo_address: &'static str,
    sender_address: &'static str,
    fee_to_sender: u128,
}

#[test]
#[ignore] // Run manually: cargo test -p krusty-kms-sdk --test cross_compat -- --ignored --nocapture
fn generate_cross_compat_vectors() {
    let fund_cases = vec![
        FundCase {
            name: "fund_zero_balance",
            description: "Fund 100 from zero balance, fee_to_sender=0",
            private_key: "12345",
            amount: 100,
            initial_balance: 0,
            nonce: "1",
            chain_id: "0x534e5f5345504f4c4941",
            tongo_address: "123456789",
            sender_address: "0",
            fee_to_sender: 0,
        },
        FundCase {
            name: "fund_with_fee",
            description: "Fund 500 from zero balance with fee_to_sender=10",
            private_key: "98765",
            amount: 500,
            initial_balance: 0,
            nonce: "42",
            chain_id: "0x534e5f5345504f4c4941",
            tongo_address: "987654321",
            sender_address: "555",
            fee_to_sender: 10,
        },
    ];

    let rollover_cases = vec![RolloverCase {
        name: "rollover_basic",
        description: "Basic rollover",
        private_key: "12345",
        nonce: "1",
        chain_id: "0x534e5f5345504f4c4941",
        tongo_address: "123456789",
        sender_address: "0",
    }];

    let ragequit_cases = vec![RagequitCase {
        name: "ragequit_full",
        description: "Full withdrawal of 1000, fee_to_sender=0",
        private_key: "12345",
        amount: 1000,
        send_to: "999888777",
        nonce: "1",
        chain_id: "0x534e5f5345504f4c4941",
        tongo_address: "123456789",
        sender_address: "0",
        fee_to_sender: 0,
    }];

    let mut vectors: Vec<Value> = Vec::new();

    // Generate fund vectors
    for case in &fund_cases {
        let private_key = Felt::from_dec_str(case.private_key).unwrap();
        let contract_address = Felt::from_dec_str(case.tongo_address).unwrap();
        let mut account = TongoAccount::from_private_key(private_key, contract_address).unwrap();
        account.state.balance = case.initial_balance;

        let nonce = Felt::from_dec_str(case.nonce).unwrap();
        let chain_id = Felt::from_hex_unchecked(case.chain_id);
        let tongo_address = Felt::from_dec_str(case.tongo_address).unwrap();
        let sender_address = Felt::from_dec_str(case.sender_address).unwrap();

        let g = StarkCurve::generator();
        let current_balance = ElGamalCiphertext { l: g.clone(), r: g };

        let params = FundParams {
            amount: case.amount,
            nonce,
            chain_id,
            tongo_address,
            sender_address,
            fee_to_sender: case.fee_to_sender,
            auditor_pub_key: None,
            current_balance,
        };
        let proof = fund(&account, params).expect("Fund operation failed");

        let vector = json!({
            "operation": "fund",
            "name": case.name,
            "description": case.description,
            "inputs": {
                "y": point_to_json(&proof.y),
                "amount": case.amount.to_string(),
                "nonce": case.nonce,
                "prefix_data": {
                    "chain_id": case.chain_id,
                    "tongo_address": case.tongo_address,
                    "sender_address": case.sender_address,
                },
                "relay_data": {
                    "fee_to_sender": case.fee_to_sender.to_string(),
                },
            },
            "proof": {
                "Ax": {
                    "x": proof.proof.a.x.clone(),
                    "y": proof.proof.a.y.clone(),
                },
                "sx": proof.proof.s.clone(),
            },
        });
        vectors.push(vector);
        println!("Generated: {}", case.name);
    }

    // Generate rollover vectors
    for case in &rollover_cases {
        let private_key = Felt::from_dec_str(case.private_key).unwrap();
        let contract_address = Felt::from_dec_str(case.tongo_address).unwrap();
        let account = TongoAccount::from_private_key(private_key, contract_address).unwrap();

        let nonce = Felt::from_dec_str(case.nonce).unwrap();
        let chain_id = Felt::from_hex_unchecked(case.chain_id);
        let tongo_address = Felt::from_dec_str(case.tongo_address).unwrap();
        let sender_address = Felt::from_dec_str(case.sender_address).unwrap();

        let params = RolloverParams {
            nonce,
            chain_id,
            tongo_address,
            sender_address,
        };
        let proof = rollover(&account, params).expect("Rollover operation failed");

        let vector = json!({
            "operation": "rollover",
            "name": case.name,
            "description": case.description,
            "inputs": {
                "y": point_to_json(&account.keypair.public_key),
                "nonce": case.nonce,
                "prefix_data": {
                    "chain_id": case.chain_id,
                    "tongo_address": case.tongo_address,
                    "sender_address": case.sender_address,
                },
            },
            "proof": {
                "Ax": {
                    "x": proof.proof.a.x.clone(),
                    "y": proof.proof.a.y.clone(),
                },
                "sx": proof.proof.s.clone(),
            },
        });
        vectors.push(vector);
        println!("Generated: {}", case.name);
    }

    // Generate ragequit vectors
    for case in &ragequit_cases {
        let private_key = Felt::from_dec_str(case.private_key).unwrap();
        let contract_address = Felt::from_dec_str(case.tongo_address).unwrap();
        let mut account = TongoAccount::from_private_key(private_key, contract_address).unwrap();
        account.state.balance = case.amount;

        let nonce = Felt::from_dec_str(case.nonce).unwrap();
        let chain_id = Felt::from_hex_unchecked(case.chain_id);
        let tongo_address = Felt::from_dec_str(case.tongo_address).unwrap();
        let sender_address = Felt::from_dec_str(case.sender_address).unwrap();
        let recipient_address = Felt::from_dec_str(case.send_to).unwrap();

        // Create current balance cipher: L = g^amount + y^1, R = g^1
        // This matches ElGamal with randomness r=1
        let g = StarkCurve::generator();
        let g_amount = StarkCurve::mul(&Felt::from(case.amount), Some(&g));
        let l = StarkCurve::add(&g_amount, &account.keypair.public_key);
        let current_balance = ElGamalCiphertext { l, r: g };

        let params = RagequitParams {
            recipient_address,
            nonce,
            chain_id,
            tongo_address,
            sender_address,
            fee_to_sender: case.fee_to_sender,
            current_balance: current_balance.clone(),
            auditor_key: None,
        };
        let proof = ragequit(&account, params).expect("Ragequit operation failed");

        let vector = json!({
            "operation": "ragequit",
            "name": case.name,
            "description": case.description,
            "inputs": {
                "y": point_to_json(&proof.y),
                "nonce": case.nonce,
                "to": case.send_to,
                "amount": case.amount.to_string(),
                "currentBalance": {
                    "L": point_to_json(&current_balance.l),
                    "R": point_to_json(&current_balance.r),
                },
                "prefix_data": {
                    "chain_id": case.chain_id,
                    "tongo_address": case.tongo_address,
                    "sender_address": case.sender_address,
                },
                "relay_data": {
                    "fee_to_sender": case.fee_to_sender.to_string(),
                },
            },
            "proof": {
                "Ax": point_to_json(&proof.a_x),
                "AR": point_to_json(&proof.a_r),
                "sx": felt_to_hex(&proof.sx),
            },
        });
        vectors.push(vector);
        println!("Generated: {}", case.name);
    }

    let output = json!({
        "generated": "2026-03-06",
        "description": "Cross-SDK compatibility vectors: Rust proofs to be verified by TypeScript tongo-sdk",
        "totalVectors": vectors.len(),
        "vectors": vectors,
    });

    let output_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../cross-compat-vectors.json"
    );
    let pretty = serde_json::to_string_pretty(&output).expect("Failed to serialize");
    fs::write(output_path, &pretty).expect("Failed to write cross-compat-vectors.json");
    println!("\nWrote {} vectors to {}", vectors.len(), output_path);
}
