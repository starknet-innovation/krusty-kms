//! Test vector validation for cryptographic primitives.
//!
//! This test suite validates the Rust implementation against the TypeScript
//! reference implementation using the generated test vectors.

use serde::Deserialize;
use serde_json;
use krusty_kms_crypto::*;
use starknet_types_core::felt::Felt;
use std::fs;

#[derive(Debug, Deserialize)]
struct TestVectors {
    vectors: Vec<TestVector>,
}

#[derive(Debug, Deserialize)]
struct TestVector {
    category: String,
    name: String,
    inputs: serde_json::Value,
    expected: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct PointExpected {
    x: String,
    y: String,
}

#[test]
fn test_point_arithmetic_vectors() {
    let test_vectors_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors.json");

    // Skip if test vectors don't exist (they're gitignored)
    if !std::path::Path::new(test_vectors_path).exists() {
        eprintln!("Skipping test: test-vectors.json not found at {}", test_vectors_path);
        return;
    }

    let contents = fs::read_to_string(test_vectors_path)
        .expect("Failed to read test vectors");

    let test_data: TestVectors = serde_json::from_str(&contents)
        .expect("Failed to parse test vectors");

    for vector in test_data.vectors.iter().filter(|v| v.category == "point_arithmetic") {
        let scalar_str = vector.inputs["scalar"].as_str().unwrap();
        let scalar = Felt::from_dec_str(scalar_str).unwrap();

        let result = StarkCurve::mul_generator(&scalar);
        let result_affine = StarkCurve::projective_to_affine(&result).unwrap();

        let expected: PointExpected = serde_json::from_value(vector.expected.clone()).unwrap();
        let expected_x = Felt::from_dec_str(&expected.x).unwrap();
        let expected_y = Felt::from_dec_str(&expected.y).unwrap();

        assert_eq!(
            result_affine.x(), expected_x,
            "Vector {} failed: x coordinate mismatch",
            vector.name
        );
        assert_eq!(
            result_affine.y(), expected_y,
            "Vector {} failed: y coordinate mismatch",
            vector.name
        );
    }
}

#[test]
fn test_poe_protocol_vectors() {
    let test_vectors_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors.json");

    if !std::path::Path::new(test_vectors_path).exists() {
        eprintln!("Skipping test: test-vectors.json not found");
        return;
    }

    let contents = fs::read_to_string(test_vectors_path)
        .expect("Failed to read test vectors");

    let test_data: TestVectors = serde_json::from_str(&contents)
        .expect("Failed to parse test vectors");

    for vector in test_data.vectors.iter().filter(|v| v.category == "poe_protocol") {
        let x_str = vector.inputs["x"].as_str().unwrap();
        let prefix_str = vector.inputs["prefix"].as_str().unwrap();

        let x = Felt::from_dec_str(x_str).unwrap();
        let prefix = Felt::from_dec_str(prefix_str).unwrap();

        // Note: Since the proof uses randomness, we can't match the exact proof
        // but we can verify that our generated proof is valid
        let (y, proof) = ProofOfExponentiation::prove(&x, &prefix).unwrap();
        let valid = ProofOfExponentiation::verify(&y, &proof, &prefix).unwrap();

        assert!(valid, "Generated proof for {} should be valid", vector.name);

        // Verify the y value matches expected
        let expected_y: PointExpected = serde_json::from_value(vector.expected["y"].clone()).unwrap();
        let expected_y_x = Felt::from_dec_str(&expected_y.x).unwrap();
        let expected_y_y = Felt::from_dec_str(&expected_y.y).unwrap();

        let y_affine = StarkCurve::projective_to_affine(&y).unwrap();
        assert_eq!(
            y_affine.x(), expected_y_x,
            "Vector {} failed: y.x mismatch",
            vector.name
        );
        assert_eq!(
            y_affine.y(), expected_y_y,
            "Vector {} failed: y.y mismatch",
            vector.name
        );
    }
}

#[test]
fn test_poe2_protocol_vectors() {
    let test_vectors_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors.json");

    if !std::path::Path::new(test_vectors_path).exists() {
        eprintln!("Skipping test: test-vectors.json not found");
        return;
    }

    let contents = fs::read_to_string(test_vectors_path)
        .expect("Failed to read test vectors");

    let test_data: TestVectors = serde_json::from_str(&contents)
        .expect("Failed to parse test vectors");

    for vector in test_data.vectors.iter().filter(|v| v.category == "poe2_protocol") {
        let x1_str = vector.inputs["x1"].as_str().unwrap();
        let x2_str = vector.inputs["x2"].as_str().unwrap();
        let prefix_str = vector.inputs["prefix"].as_str().unwrap();

        let x1 = Felt::from_dec_str(x1_str).unwrap();
        let x2 = Felt::from_dec_str(x2_str).unwrap();
        let prefix = Felt::from_dec_str(prefix_str).unwrap();

        // Use the standard generator points G and H
        let g = StarkCurve::generator();
        let h = StarkCurve::generator_h();

        let (y, proof) = ProofOfExponentiation2::prove(&x1, &x2, &g, &h, &prefix).unwrap();
        let valid = ProofOfExponentiation2::verify(&y, &g, &h, &proof, &prefix).unwrap();

        assert!(valid, "Generated proof for {} should be valid", vector.name);

        // Verify the y value matches expected
        let expected_y: PointExpected = serde_json::from_value(vector.expected["y"].clone()).unwrap();
        let expected_y_x = Felt::from_dec_str(&expected_y.x).unwrap();
        let expected_y_y = Felt::from_dec_str(&expected_y.y).unwrap();

        let y_affine = StarkCurve::projective_to_affine(&y).unwrap();
        assert_eq!(
            y_affine.x(), expected_y_x,
            "Vector {} failed: y.x mismatch",
            vector.name
        );
        assert_eq!(
            y_affine.y(), expected_y_y,
            "Vector {} failed: y.y mismatch",
            vector.name
        );
    }
}

#[test]
fn test_elgamal_protocol_vectors() {
    let test_vectors_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors.json");

    if !std::path::Path::new(test_vectors_path).exists() {
        eprintln!("Skipping test: test-vectors.json not found");
        return;
    }

    let contents = fs::read_to_string(test_vectors_path)
        .expect("Failed to read test vectors");

    let test_data: TestVectors = serde_json::from_str(&contents)
        .expect("Failed to parse test vectors");

    for vector in test_data.vectors.iter().filter(|v| v.category == "elgamal_protocol") {
        let message_str = vector.inputs["message"].as_str().unwrap();
        let random_str = vector.inputs["random"].as_str().unwrap();
        let prefix_str = vector.inputs["prefix"].as_str().unwrap();

        let message = Felt::from_dec_str(message_str).unwrap();
        let random = Felt::from_dec_str(random_str).unwrap();
        let prefix = Felt::from_dec_str(prefix_str).unwrap();

        // For ElGamal, we need a public key (using generator for test)
        let sk = Felt::from(42u64);
        let pk = StarkCurve::mul_generator(&sk);

        let encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();
        let valid = ElGamal::verify(&encryption.l, &encryption.r, &pk, &encryption.proof, &prefix).unwrap();

        assert!(valid, "Generated proof for {} should be valid", vector.name);
    }
}
