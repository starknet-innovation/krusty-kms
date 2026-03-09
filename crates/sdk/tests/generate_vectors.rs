//! Generator for prover test vectors.
//!
//! Run with: cargo test -p krusty-kms-sdk --test generate_vectors -- --ignored --nocapture

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
        "x": affine.x().to_string(),
        "y": affine.y().to_string(),
    })
}

fn cipher_to_json(cipher: &ElGamalCiphertext) -> Value {
    json!({
        "L": point_to_json(&cipher.l),
        "R": point_to_json(&cipher.r),
    })
}

fn poe_proof_to_json(proof: &krusty_kms_common::PoeProof) -> Value {
    json!({
        "Ax": {
            "x": proof.a.x.clone(),
            "y": proof.a.y.clone(),
        },
        "sx": proof.s.clone(),
    })
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
}

struct RolloverCase {
    name: &'static str,
    description: &'static str,
    private_key: &'static str,
    nonce: &'static str,
    chain_id: &'static str,
    tongo_address: &'static str,
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
}

#[test]
#[ignore] // Run manually: cargo test -p krusty-kms-sdk --test generate_vectors -- --ignored --nocapture
fn generate_prover_vectors() {
    let fund_cases = vec![
        FundCase {
            name: "fund_small_amount",
            description: "Fund with a small amount (100) from zero balance",
            private_key: "12345",
            amount: 100,
            initial_balance: 0,
            nonce: "1",
            chain_id: "0x534e5f5345504f4c4941",
            tongo_address: "123456789",
        },
        FundCase {
            name: "fund_large_amount",
            description: "Fund with a larger amount (1000000) from zero balance",
            private_key: "98765",
            amount: 1_000_000,
            initial_balance: 0,
            nonce: "42",
            chain_id: "0x534e5f5345504f4c4941",
            tongo_address: "987654321",
        },
        FundCase {
            name: "fund_with_existing_balance",
            description: "Fund with existing balance of 500",
            private_key: "55555",
            amount: 250,
            initial_balance: 500,
            nonce: "7",
            chain_id: "0x534e5f5345504f4c4941",
            tongo_address: "111222333",
        },
    ];

    let rollover_cases = vec![
        RolloverCase {
            name: "rollover_basic",
            description: "Basic rollover operation",
            private_key: "12345",
            nonce: "1",
            chain_id: "0x534e5f5345504f4c4941",
            tongo_address: "123456789",
        },
        RolloverCase {
            name: "rollover_different_key",
            description: "Rollover with a different private key",
            private_key: "67890",
            nonce: "99",
            chain_id: "0x534e5f5345504f4c4941",
            tongo_address: "555666777",
        },
    ];

    let ragequit_cases = vec![
        RagequitCase {
            name: "ragequit_full_withdrawal",
            description: "Full withdrawal of balance 1000",
            private_key: "12345",
            amount: 1000,
            send_to: "999888777",
            nonce: "1",
            chain_id: "0x534e5f5345504f4c4941",
            tongo_address: "123456789",
        },
        RagequitCase {
            name: "ragequit_small_balance",
            description: "Full withdrawal of small balance 10",
            private_key: "54321",
            amount: 10,
            send_to: "111222333",
            nonce: "5",
            chain_id: "0x534e5f5345504f4c4941",
            tongo_address: "444555666",
        },
    ];

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

        let g = StarkCurve::generator();
        let current_balance = ElGamalCiphertext { l: g.clone(), r: g };

        let params = FundParams {
            amount: case.amount,
            nonce,
            chain_id,
            tongo_address,
            sender_address: Felt::from(0u64),

            auditor_pub_key: None,
            current_balance,
        };
        let proof = fund(&account, params).expect("Fund operation failed");

        let vector = json!({
            "category": "fund_prover",
            "name": case.name,
            "description": case.description,
            "inputs": {
                "privateKey": case.private_key,
                "amountToFund": case.amount.to_string(),
                "initialBalance": case.initial_balance.to_string(),
                "nonce": case.nonce,
                "chainId": case.chain_id,
                "tongoAddress": case.tongo_address,
            },
            "expected": {
                "inputs": {
                    "y": point_to_json(&proof.y),
                    "amount": case.amount.to_string(),
                    "nonce": case.nonce,
                    "prefixData": {
                        "chainId": case.chain_id,
                        "tongoAddress": case.tongo_address,
                    },
                },
                "proof": poe_proof_to_json(&proof.proof),
                "newBalance": {
                    "L": point_to_json(&proof.y),
                    "R": point_to_json(&proof.y),
                },
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

        let params = RolloverParams {
            nonce,
            chain_id,
            tongo_address,
            sender_address: Felt::from(0u64),
        };
        let proof = rollover(&account, params).expect("Rollover operation failed");

        let vector = json!({
            "category": "rollover_prover",
            "name": case.name,
            "description": case.description,
            "inputs": {
                "privateKey": case.private_key,
                "nonce": case.nonce,
                "chainId": case.chain_id,
                "tongoAddress": case.tongo_address,
            },
            "expected": {
                "inputs": {
                    "y": point_to_json(&proof.y),
                    "nonce": case.nonce,
                    "prefixData": {
                        "chainId": case.chain_id,
                        "tongoAddress": case.tongo_address,
                    },
                },
                "proof": poe_proof_to_json(&proof.proof),
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
        let recipient_address = Felt::from_dec_str(case.send_to).unwrap();

        let g = StarkCurve::generator();
        let g_amount = StarkCurve::mul(&Felt::from(case.amount), Some(&g));
        let l = StarkCurve::add(&g_amount, &account.keypair.public_key);
        let current_balance = ElGamalCiphertext { l, r: g };

        let params = RagequitParams {
            recipient_address,
            nonce,
            chain_id,
            tongo_address,
            sender_address: Felt::from(0u64),

            current_balance: current_balance.clone(),
            auditor_key: None,
        };
        let proof = ragequit(&account, params).expect("Ragequit operation failed");

        let vector = json!({
            "category": "ragequit_prover",
            "name": case.name,
            "description": case.description,
            "inputs": {
                "privateKey": case.private_key,
                "fullAmount": case.amount.to_string(),
                "sendTo": case.send_to,
                "nonce": case.nonce,
                "chainId": case.chain_id,
                "tongoAddress": case.tongo_address,
            },
            "expected": {
                "inputs": {
                    "y": point_to_json(&proof.y),
                    "nonce": case.nonce,
                    "to": case.send_to,
                    "amount": case.amount.to_string(),
                    "currentBalance": cipher_to_json(&current_balance),
                    "prefixData": {
                        "chainId": case.chain_id,
                        "tongoAddress": case.tongo_address,
                    },
                },
                "proof": {
                    "Ax": point_to_json(&proof.a_x),
                    "AR": point_to_json(&proof.a_r),
                    "sx": format!("{:#x}", proof.sx),
                },
                "newBalance": {
                    "L": point_to_json(&proof.y),
                    "R": point_to_json(&proof.y),
                },
            },
        });
        vectors.push(vector);
        println!("Generated: {}", case.name);
    }

    let output = json!({
        "generated": "2026-03-06",
        "description": "Prover test vectors generated from krusty-kms-sdk Rust implementation",
        "totalVectors": vectors.len(),
        "vectors": vectors,
    });

    let output_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../prover-vectors.json");
    let pretty = serde_json::to_string_pretty(&output).expect("Failed to serialize");
    fs::write(output_path, &pretty).expect("Failed to write prover-vectors.json");
    println!("\nWrote {} vectors to {}", vectors.len(), output_path);
}
