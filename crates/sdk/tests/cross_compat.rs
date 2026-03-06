//! Cross-SDK compatibility test vectors.
//!
//! Generates proof data that can be verified by the TypeScript tongo-sdk.
//! Run with: cargo test -p krusty-kms-sdk --test cross_compat -- --ignored --nocapture

use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_crypto::StarkCurve;
use krusty_kms_sdk::operations::{
    fund, ragequit, rollover, transfer, withdraw, FundParams, RagequitParams, RolloverParams,
    TransferParams, WithdrawParams,
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

struct WithdrawCase {
    name: &'static str,
    description: &'static str,
    private_key: &'static str,
    balance: u128,
    amount: u128,
    send_to: &'static str,
    nonce: &'static str,
    chain_id: &'static str,
    tongo_address: &'static str,
    sender_address: &'static str,
    fee_to_sender: u128,
    bit_size: usize,
}

struct TransferCase {
    name: &'static str,
    description: &'static str,
    private_key: &'static str,
    recipient_key: &'static str,
    balance: u128,
    amount: u128,
    nonce: &'static str,
    chain_id: &'static str,
    tongo_address: &'static str,
    sender_address: &'static str,
    fee_to_sender: u128,
    bit_size: usize,
}

fn cipher_to_json(cipher: &ElGamalCiphertext) -> Value {
    json!({
        "L": point_to_json(&cipher.l),
        "R": point_to_json(&cipher.r),
    })
}

fn range_to_json(range: &krusty_kms_common::Range) -> Value {
    let commitments: Vec<Value> = range
        .commitments
        .iter()
        .map(|c| json!({"x": c.x, "y": c.y}))
        .collect();
    let proofs: Vec<Value> = range
        .proofs
        .iter()
        .map(|p| {
            json!({
                "A0": {"x": p.a0.x, "y": p.a0.y},
                "A1": {"x": p.a1.x, "y": p.a1.y},
                "c0": p.c0,
                "s0": p.s0,
                "s1": p.s1,
            })
        })
        .collect();
    json!({
        "commitments": commitments,
        "proofs": proofs,
    })
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

    // Generate withdraw vectors
    let withdraw_cases = vec![WithdrawCase {
        name: "withdraw_partial",
        description: "Withdraw 300 from balance of 1000, fee_to_sender=0",
        private_key: "12345",
        balance: 1000,
        amount: 300,
        send_to: "999888777",
        nonce: "1",
        chain_id: "0x534e5f5345504f4c4941",
        tongo_address: "123456789",
        sender_address: "0",
        fee_to_sender: 0,
        bit_size: 32,
    }];

    for case in &withdraw_cases {
        let private_key = Felt::from_dec_str(case.private_key).unwrap();
        let contract_address = Felt::from_dec_str(case.tongo_address).unwrap();
        let mut account = TongoAccount::from_private_key(private_key, contract_address).unwrap();
        account.state.balance = case.balance;

        let nonce = Felt::from_dec_str(case.nonce).unwrap();
        let chain_id = Felt::from_hex_unchecked(case.chain_id);
        let tongo_address = Felt::from_dec_str(case.tongo_address).unwrap();
        let sender_address = Felt::from_dec_str(case.sender_address).unwrap();
        let recipient_address = Felt::from_dec_str(case.send_to).unwrap();

        // Create current balance cipher with randomness r=1
        let g = StarkCurve::generator();
        let g_amount = StarkCurve::mul(&Felt::from(case.balance), Some(&g));
        let l = StarkCurve::add(&g_amount, &account.keypair.public_key);
        let current_balance = ElGamalCiphertext { l, r: g };

        let params = WithdrawParams {
            recipient_address,
            amount: case.amount,
            nonce,
            chain_id,
            tongo_address,
            sender_address,
            fee_to_sender: case.fee_to_sender,
            current_balance: current_balance.clone(),
            bit_size: case.bit_size,
            auditor_key: None,
        };
        let proof = withdraw(&account, params).expect("Withdraw operation failed");

        let vector = json!({
            "operation": "withdraw",
            "name": case.name,
            "description": case.description,
            "inputs": {
                "y": point_to_json(&proof.y),
                "nonce": case.nonce,
                "to": case.send_to,
                "amount": case.amount.to_string(),
                "currentBalance": cipher_to_json(&current_balance),
                "auxiliarCipher": cipher_to_json(&proof.auxiliar_cipher),
                "bit_size": case.bit_size,
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
                "A_x": point_to_json(&proof.a_x),
                "A_r": point_to_json(&proof.a_r),
                "A": point_to_json(&proof.a),
                "A_v": point_to_json(&proof.a_v),
                "sx": felt_to_hex(&proof.sx),
                "sb": felt_to_hex(&proof.sb),
                "sr": felt_to_hex(&proof.sr),
                "range": range_to_json(&proof.range),
            },
        });
        vectors.push(vector);
        println!("Generated: {}", case.name);
    }

    // Generate transfer vectors
    let transfer_cases = vec![TransferCase {
        name: "transfer_basic",
        description: "Transfer 200 from balance of 1000, fee_to_sender=0",
        private_key: "12345",
        recipient_key: "67890",
        balance: 1000,
        amount: 200,
        nonce: "1",
        chain_id: "0x534e5f5345504f4c4941",
        tongo_address: "123456789",
        sender_address: "0",
        fee_to_sender: 0,
        bit_size: 32,
    }];

    for case in &transfer_cases {
        let private_key = Felt::from_dec_str(case.private_key).unwrap();
        let contract_address = Felt::from_dec_str(case.tongo_address).unwrap();
        let mut account = TongoAccount::from_private_key(private_key, contract_address).unwrap();
        account.state.balance = case.balance;

        let recipient_private_key = Felt::from_dec_str(case.recipient_key).unwrap();
        let recipient_pub_key =
            StarkCurve::mul(&recipient_private_key, Some(&StarkCurve::generator()));

        let nonce = Felt::from_dec_str(case.nonce).unwrap();
        let chain_id = Felt::from_hex_unchecked(case.chain_id);
        let tongo_address = Felt::from_dec_str(case.tongo_address).unwrap();
        let sender_address = Felt::from_dec_str(case.sender_address).unwrap();

        // Create current balance cipher with randomness r=1
        let g = StarkCurve::generator();
        let g_amount = StarkCurve::mul(&Felt::from(case.balance), Some(&g));
        let l = StarkCurve::add(&g_amount, &account.keypair.public_key);
        let current_balance = ElGamalCiphertext { l, r: g };

        let params = TransferParams {
            recipient_public_key: recipient_pub_key.clone(),
            amount: case.amount,
            nonce,
            chain_id,
            tongo_address,
            sender_address,
            fee_to_sender: case.fee_to_sender,
            current_balance: current_balance.clone(),
            bit_size: case.bit_size,
            auditor_pub_key: None,
        };
        let proof = transfer(&account, params).expect("Transfer operation failed");

        let vector = json!({
            "operation": "transfer",
            "name": case.name,
            "description": case.description,
            "inputs": {
                "from": point_to_json(&account.keypair.public_key),
                "to": point_to_json(&recipient_pub_key),
                "nonce": case.nonce,
                "currentBalance": cipher_to_json(&current_balance),
                "transferBalance": {
                    "L": point_to_json(&proof.transfer_balance_l),
                    "R": point_to_json(&proof.transfer_balance_r),
                },
                "transferBalanceSelf": {
                    "L": point_to_json(&proof.transfer_balance_self_l),
                    "R": point_to_json(&proof.transfer_balance_self_r),
                },
                "auxiliarCipher": cipher_to_json(&proof.auxiliar_cipher),
                "auxiliarCipher2": cipher_to_json(&proof.auxiliar_cipher2),
                "bit_size": case.bit_size,
                "prefix_data": {
                    "chain_id": case.chain_id,
                    "tongo_address": case.tongo_address,
                    "sender_address": case.sender_address,
                },
                "relay_data": {
                    "fee_to_sender": case.fee_to_sender.to_string(),
                },
            },
            "proof": serde_json::to_value(&proof.proof).unwrap(),
        });
        vectors.push(vector);
        println!("Generated: {}", case.name);
    }

    let output = json!({
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
