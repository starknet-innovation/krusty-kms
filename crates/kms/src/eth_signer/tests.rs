//! Tests for the Ethereum secp256k1 signer.

use super::*;

// A well-known test private key (DO NOT use in production).
const TEST_KEY_HEX: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[test]
fn test_from_private_key() {
    let bytes =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let signer = EthSigner::from_private_key(&arr);
    assert!(signer.is_ok());
}

#[test]
fn test_from_hex() {
    let signer = EthSigner::from_hex(TEST_KEY_HEX);
    assert!(signer.is_ok());
}

#[test]
fn test_from_hex_no_prefix() {
    let signer =
        EthSigner::from_hex("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    assert!(signer.is_ok());
}

#[test]
fn test_from_hex_invalid_length() {
    let result = EthSigner::from_hex("0xDEADBEEF");
    assert!(result.is_err());
}

#[test]
fn test_public_key_uncompressed() {
    let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
    let pubkey = signer.public_key_uncompressed();
    // Uncompressed key starts with 0x04
    assert_eq!(pubkey[0], 0x04);
    assert_eq!(pubkey.len(), 65);
}

/// Known answers: the Hardhat development accounts 0 and 1, whose
/// uncompressed public keys are published with the keys. Limbs were
/// computed outside this crate (pure-integer secp256k1 scalar
/// multiplication), so the test does not compare the code with itself.
/// Regression test for audit finding H-1 (2026-11-04): coordinates were
/// reduced modulo the Stark prime before being split.
#[test]
fn public_key_calldata_known_answers() {
    let cases = [
        (
            TEST_KEY_HEX,
            [
                "0x87181b4fdfc625bd1a753fa7397fed75",
                "0x8318535b54105d4a7aae60c08fc45f96",
                "0xfac23e630c5d11f59f61fef57b0d2aa5",
                "0x3547f11ca8696646f2f3acb08e31016a",
            ],
        ),
        (
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
            [
                "0x0dc70cc661ca05e688601ad984f068b0",
                "0xba5734d8f7091719471e7f7ed6b9df17",
                "0xa521afd334e53807205fa2f08eec74f4",
                "0xd67351e5f06073092499336ab0839ef8",
            ],
        ),
    ];
    for (key, expected) in cases {
        let signer = EthSigner::from_hex(key).unwrap();
        let expected = expected.map(|limb| Felt::from_hex(limb).unwrap());
        assert_eq!(signer.public_key_calldata(), expected, "{key}");
    }
}

#[test]
fn public_key_calldata_splits_sec1_coordinates() {
    let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
    let sec1 = signer.public_key_uncompressed();
    let limb = |range: std::ops::Range<usize>| {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&sec1[range]);
        Felt::from(u128::from_be_bytes(buf))
    };
    assert_eq!(
        signer.public_key_calldata(),
        [limb(17..33), limb(1..17), limb(49..65), limb(33..49)]
    );
}

#[test]
fn test_public_key_xy() {
    let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
    let (x, y) = signer.public_key_xy();
    // Both coordinates should be non-zero
    assert_ne!(x.to_bytes_be(), [0u8; 32]);
    assert_ne!(y.to_bytes_be(), [0u8; 32]);
}

#[test]
fn test_public_key_xy_matches_uncompressed() {
    let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
    let (x, y) = signer.public_key_xy();
    let uncompressed = signer.public_key_uncompressed();

    assert_eq!(x.to_bytes_be()[..], uncompressed[1..33]);
    assert_eq!(y.to_bytes_be()[..], uncompressed[33..65]);
}

#[test]
fn test_public_key_coordinates_round_trip_through_u256() {
    let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
    let (x, y) = signer.public_key_xy();
    let uncompressed = signer.public_key_uncompressed();

    for (coordinate, expected) in [(x, &uncompressed[1..33]), (y, &uncompressed[33..65])] {
        // This fixture exercises coordinates that the old Felt conversion reduced.
        let reduced = Felt::from_bytes_be_slice(expected);
        assert_ne!(coordinate.to_bytes_be(), reduced.to_bytes_be());

        let (low, high) = coordinate.to_u256_pair();
        let low_bytes = low.to_bytes_be();
        let high_bytes = high.to_bytes_be();
        assert_eq!(&low_bytes[..16], &[0u8; 16]);
        assert_eq!(&high_bytes[..16], &[0u8; 16]);
        assert_eq!(&low_bytes[16..], &expected[16..]);
        assert_eq!(&high_bytes[16..], &expected[..16]);

        let mut reconstructed = [0u8; 32];
        reconstructed[..16].copy_from_slice(&high_bytes[16..]);
        reconstructed[16..].copy_from_slice(&low_bytes[16..]);
        assert_eq!(reconstructed.as_slice(), expected);
    }
}

#[test]
fn test_sign_hash() {
    let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
    let hash = Felt::from(0x1234567890ABCDEFu64);
    let sig = signer.sign_hash(&hash).unwrap();

    // Should return 5 Felts
    assert_eq!(sig.len(), 5);
    // r_low, r_high, s_low, s_high should be non-zero
    // (statistically impossible for both halves to be zero)
    assert!(sig[0] != Felt::ZERO || sig[1] != Felt::ZERO); // r
    assert!(sig[2] != Felt::ZERO || sig[3] != Felt::ZERO); // s
                                                           // v should be 0 or 1
    assert!(sig[4] == Felt::ZERO || sig[4] == Felt::ONE);
}

#[test]
fn test_sign_hash_deterministic() {
    let signer = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
    let hash = Felt::from(42u64);
    let sig1 = signer.sign_hash(&hash).unwrap();
    let sig2 = signer.sign_hash(&hash).unwrap();
    assert_eq!(sig1, sig2);
}

#[test]
fn test_u256_split_correctness() {
    // A known 32-byte value
    let mut bytes = [0u8; 32];
    // Set low bytes to 1
    bytes[31] = 1;
    let (low, high) = bytes32_to_u256_pair(&bytes);
    assert_eq!(low, Felt::ONE);
    assert_eq!(high, Felt::ZERO);

    // Set high bytes
    let mut bytes2 = [0u8; 32];
    bytes2[0] = 1; // highest byte
    let (low2, high2) = bytes32_to_u256_pair(&bytes2);
    assert_eq!(low2, Felt::ZERO);
    assert_ne!(high2, Felt::ZERO);
}

#[test]
#[allow(deprecated)]
fn test_felt_to_u256_pair() {
    let felt = Felt::from(0xDEADBEEFu64);
    let (low, high) = felt_to_u256_pair(&felt);
    assert_eq!(low, Felt::from(0xDEADBEEFu64));
    assert_eq!(high, Felt::ZERO);
}

#[test]
fn test_different_keys_different_signatures() {
    let signer1 = EthSigner::from_hex(TEST_KEY_HEX).unwrap();
    let signer2 =
        EthSigner::from_hex("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
            .unwrap();

    let hash = Felt::from(42u64);
    let sig1 = signer1.sign_hash(&hash).unwrap();
    let sig2 = signer2.sign_hash(&hash).unwrap();

    // Different keys produce different signatures
    assert_ne!(sig1, sig2);
}
