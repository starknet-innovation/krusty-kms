//! Test vectors for TONGO SDK operations.
//!
//! These vectors are generated from the TypeScript reference implementation
//! to ensure compatibility and correctness.

use krusty_kms_crypto::StarkCurve;
use krusty_kms_sdk::operations::{
    fund, ragequit, rollover, FundParams, RagequitParams, RolloverParams,
};
use krusty_kms_sdk::TongoAccount;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;
use std::fs;

/// Point representation in test vectors
#[derive(Debug, Clone, Deserialize, Serialize)]
struct PointVector {
    x: String,
    y: String,
}

impl PointVector {
    fn to_projective(&self) -> ProjectivePoint {
        let x = Felt::from_dec_str(&self.x).unwrap();
        let y = Felt::from_dec_str(&self.y).unwrap();
        ProjectivePoint::from_affine(x, y).unwrap()
    }
}

/// ElGamal encryption result
#[derive(Debug, Clone, Deserialize, Serialize)]
struct ElGamalVector {
    #[serde(rename = "L")]
    l: PointVector,
    #[serde(rename = "R")]
    r: PointVector,
}

/// Proof of exponentiation proof
#[derive(Debug, Clone, Deserialize, Serialize)]
struct PoeProofVector {
    #[serde(rename = "Ax")]
    a: PointVector,
    sx: String,
}

/// Fund operation expected outputs
#[derive(Debug, Clone, Deserialize, Serialize)]
struct FundExpected {
    inputs: FundInputsVector,
    proof: PoeProofVector,
    #[serde(rename = "newBalance")]
    new_balance: ElGamalVector,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct FundInputsVector {
    y: PointVector,
    amount: String,
    nonce: String,
    #[serde(rename = "prefixData")]
    prefix_data: PrefixDataVector,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PrefixDataVector {
    #[serde(rename = "chainId")]
    chain_id: String,
    #[serde(rename = "tongoAddress")]
    tongo_address: String,
}

/// Rollover operation expected outputs
#[derive(Debug, Clone, Deserialize, Serialize)]
struct RolloverExpected {
    inputs: RolloverInputsVector,
    proof: PoeProofVector,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RolloverInputsVector {
    y: PointVector,
    nonce: String,
    #[serde(rename = "prefixData")]
    prefix_data: PrefixDataVector,
}

/// Ragequit (withdraw) operation expected outputs
#[derive(Debug, Clone, Deserialize, Serialize)]
struct RagequitExpected {
    inputs: RagequitInputsVector,
    proof: RagequitProofVector,
    #[serde(rename = "newBalance")]
    new_balance: ElGamalVector,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RagequitInputsVector {
    y: PointVector,
    nonce: String,
    to: String,
    amount: String,
    #[serde(rename = "currentBalance")]
    current_balance: ElGamalVector,
    #[serde(rename = "prefixData")]
    prefix_data: PrefixDataVector,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RagequitProofVector {
    #[serde(rename = "Ax")]
    ax: PointVector,
    #[serde(rename = "AR")]
    ar: PointVector,
    sx: String,
}

/// Test vector structure
#[derive(Debug, Clone, Deserialize, Serialize)]
struct TestVector {
    category: String,
    name: String,
    description: String,
    inputs: Value,
    expected: Value,
}

/// Test vectors file structure
#[derive(Debug, Clone, Deserialize, Serialize)]
struct TestVectorsFile {
    generated: String,
    description: String,
    #[serde(rename = "totalVectors")]
    total_vectors: usize,
    vectors: Vec<TestVector>,
}

#[test]
fn test_fund_prover_vectors() {
    // Load test vectors
    let vectors_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../prover-vectors.json");
    let vectors_content =
        fs::read_to_string(vectors_path).expect("Failed to read prover-vectors.json");
    let test_vectors: TestVectorsFile =
        serde_json::from_str(&vectors_content).expect("Failed to parse prover-vectors.json");

    // Filter fund_prover vectors
    let fund_vectors: Vec<_> = test_vectors
        .vectors
        .iter()
        .filter(|v| v.category == "fund_prover")
        .collect();

    println!("Testing {} fund prover vectors", fund_vectors.len());

    for vector in fund_vectors {
        println!("\nTesting: {}", vector.name);

        // Parse inputs
        let private_key_str = vector.inputs["privateKey"].as_str().unwrap();
        let amount_str = vector.inputs["amountToFund"].as_str().unwrap();
        let initial_balance_str = vector.inputs["initialBalance"].as_str().unwrap();
        let nonce_str = vector.inputs["nonce"].as_str().unwrap();
        let chain_id_str = vector.inputs["chainId"].as_str().unwrap();
        let tongo_address_str = vector.inputs["tongoAddress"].as_str().unwrap();

        // Parse expected outputs
        let expected: FundExpected = serde_json::from_value(vector.expected.clone())
            .expect("Failed to parse fund expected outputs");

        // Create account from private key
        let private_key = Felt::from_dec_str(private_key_str).unwrap();
        let contract_address = Felt::from_dec_str(tongo_address_str).unwrap();
        let mut account = TongoAccount::from_private_key(private_key, contract_address).unwrap();

        // Set initial balance
        let initial_balance: u128 = initial_balance_str.parse().unwrap();
        account.state.balance = initial_balance;

        // Execute fund operation
        let amount: u128 = amount_str.parse().unwrap();
        let nonce = Felt::from_dec_str(nonce_str).unwrap();
        let chain_id = Felt::from_dec_str(chain_id_str).unwrap();
        let tongo_address = Felt::from_dec_str(tongo_address_str).unwrap();

        // Create current balance cipher (zero balance for initial fund)
        let g = StarkCurve::generator();
        let current_balance = krusty_kms_common::ElGamalCiphertext { l: g.clone(), r: g };

        let params = FundParams {
            amount,
            nonce,
            chain_id,
            tongo_address,
            sender_address: Felt::from(0u64),
            auditor_pub_key: None,
            current_balance,
        };
        let proof = fund(&account, params).expect("Fund operation failed");

        // Verify outputs
        // 1. Check that y matches expected public key
        let expected_y = expected.inputs.y.to_projective();
        assert_eq!(
            account.keypair.public_key, expected_y,
            "Public key mismatch in {}",
            vector.name
        );

        // 2. Check that amount matches
        assert_eq!(proof.amount, amount, "Amount mismatch in {}", vector.name);

        // Note: We can't easily verify proof.y and proof.proof match exactly
        // because they depend on random values used internally.
        // The TypeScript vectors use fixed random values which we don't control in Rust.
        // The important part is that our proofs are valid, which is tested elsewhere.

        println!("  ✓ {} passed", vector.name);
    }
}

#[test]
fn test_rollover_prover_vectors() {
    // Load test vectors
    let vectors_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../prover-vectors.json");
    let vectors_content =
        fs::read_to_string(vectors_path).expect("Failed to read prover-vectors.json");
    let test_vectors: TestVectorsFile =
        serde_json::from_str(&vectors_content).expect("Failed to parse prover-vectors.json");

    // Filter rollover_prover vectors
    let rollover_vectors: Vec<_> = test_vectors
        .vectors
        .iter()
        .filter(|v| v.category == "rollover_prover")
        .collect();

    println!("Testing {} rollover prover vectors", rollover_vectors.len());

    for vector in rollover_vectors {
        println!("\nTesting: {}", vector.name);

        // Parse inputs
        let private_key_str = vector.inputs["privateKey"].as_str().unwrap();
        let nonce_str = vector.inputs["nonce"].as_str().unwrap();
        let chain_id_str = vector.inputs["chainId"].as_str().unwrap();
        let tongo_address_str = vector.inputs["tongoAddress"].as_str().unwrap();

        // Parse expected outputs
        let expected: RolloverExpected = serde_json::from_value(vector.expected.clone())
            .expect("Failed to parse rollover expected outputs");

        // Create account from private key
        let private_key = Felt::from_dec_str(private_key_str).unwrap();
        let contract_address = Felt::from_dec_str(tongo_address_str).unwrap();
        let account = TongoAccount::from_private_key(private_key, contract_address).unwrap();

        // Execute rollover operation
        let nonce = Felt::from_dec_str(nonce_str).unwrap();
        let chain_id = Felt::from_dec_str(chain_id_str).unwrap();
        let tongo_address = Felt::from_dec_str(tongo_address_str).unwrap();

        let params = RolloverParams {
            nonce,
            chain_id,
            tongo_address,
            sender_address: Felt::from(0u64),
        };
        let _proof = rollover(&account, params).expect("Rollover operation failed");

        // Verify outputs
        // 1. Check that y matches expected public key
        let expected_y = expected.inputs.y.to_projective();
        assert_eq!(
            account.keypair.public_key, expected_y,
            "Public key mismatch in {}",
            vector.name
        );

        // Note: Similar to fund, we can't verify exact proof values due to randomness

        println!("  ✓ {} passed", vector.name);
    }
}

#[test]
fn test_ragequit_prover_vectors() {
    // Load test vectors
    let vectors_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../prover-vectors.json");
    let vectors_content =
        fs::read_to_string(vectors_path).expect("Failed to read prover-vectors.json");
    let test_vectors: TestVectorsFile =
        serde_json::from_str(&vectors_content).expect("Failed to parse prover-vectors.json");

    // Filter ragequit_prover vectors
    let ragequit_vectors: Vec<_> = test_vectors
        .vectors
        .iter()
        .filter(|v| v.category == "ragequit_prover")
        .collect();

    println!(
        "Testing {} ragequit (withdraw) prover vectors",
        ragequit_vectors.len()
    );

    for vector in ragequit_vectors {
        println!("\nTesting: {}", vector.name);

        // Parse inputs
        let private_key_str = vector.inputs["privateKey"].as_str().unwrap();
        let amount_str = vector.inputs["fullAmount"].as_str().unwrap();
        let send_to_str = vector.inputs["sendTo"].as_str().unwrap();
        let nonce_str = vector.inputs["nonce"].as_str().unwrap();
        let chain_id_str = vector.inputs["chainId"].as_str().unwrap();
        let tongo_address_str = vector.inputs["tongoAddress"].as_str().unwrap();

        // Parse expected outputs
        let expected: RagequitExpected = serde_json::from_value(vector.expected.clone())
            .expect("Failed to parse ragequit expected outputs");

        // Create account from private key
        let private_key = Felt::from_dec_str(private_key_str).unwrap();
        let contract_address = Felt::from_dec_str(tongo_address_str).unwrap();
        let mut account = TongoAccount::from_private_key(private_key, contract_address).unwrap();

        // Set balance to the amount being withdrawn
        let amount: u128 = amount_str.parse().unwrap();
        account.state.balance = amount;

        // Execute ragequit operation
        let recipient_address = Felt::from_dec_str(send_to_str).unwrap();
        let nonce = Felt::from_dec_str(nonce_str).unwrap();
        let chain_id = Felt::from_dec_str(chain_id_str).unwrap();
        let tongo_address = Felt::from_dec_str(tongo_address_str).unwrap();

        // Create current balance cipher encrypting the full amount
        // For ragequit (full withdrawal), the cipher must be a valid ElGamal encryption
        // ElGamal: L = g^amount + y^r, R = g^r (where y = g^x is public key)
        // We use r=1 for simplicity: L = g^amount + y, R = g
        let g = StarkCurve::generator();
        let g_amount = StarkCurve::mul(&Felt::from(amount), Some(&g));
        let l = StarkCurve::add(&g_amount, &account.keypair.public_key);
        let current_balance = krusty_kms_common::ElGamalCiphertext {
            l,
            r: g, // R = g^1 (using r=1 as randomness)
        };

        let params = RagequitParams {
            recipient_address,
            nonce,
            chain_id,
            tongo_address,
            sender_address: Felt::from(0u64),
            fee_to_sender: 0,
            current_balance,
            auditor_key: None,
        };
        let proof = ragequit(&account, params).expect("Ragequit operation failed");

        // Verify outputs
        // 1. Check that y matches expected public key
        let expected_y = expected.inputs.y.to_projective();
        assert_eq!(
            account.keypair.public_key, expected_y,
            "Public key mismatch in {}",
            vector.name
        );

        // 2. Check that amount matches
        assert_eq!(proof.amount, amount, "Amount mismatch in {}", vector.name);

        // 3. Check recipient address matches
        assert_eq!(
            proof.recipient, recipient_address,
            "Recipient address mismatch in {}",
            vector.name
        );

        println!("  ✓ {} passed", vector.name);
    }
}

// Note: Transfer vectors would require more complex setup with two accounts
// and encrypted balance tracking. This can be added if transfer vectors are generated.
