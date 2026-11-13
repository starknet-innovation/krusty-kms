//! Unit tests for the encryption boundary.

use super::*;

// Use a low scrypt N for fast tests
const TEST_SCRYPT_N: u32 = 1024;

// A nonce length must be validated, not asserted.

#[test]
fn decrypt_with_key_rejects_wrong_nonce_length_without_panicking() {
    // `XNonce::from_slice` asserts on a length mismatch, so a nonce taken
    // from untrusted JSON used to abort the process instead of erroring.
    let key = test_key(0);
    for len in [0usize, 4, 12, 23, 25, 64] {
        let payload = EncryptedPayload {
            nonce: synthetic_nonce(len),
            ciphertext: vec![0u8; 48],
        };
        let err = decrypt_with_key(&payload, &key).expect_err("must be rejected");
        assert!(
            format!("{err}").contains("Invalid nonce length"),
            "len={len}, got {err}"
        );
    }
}

#[test]
fn decrypt_private_key_rejects_wrong_nonce_length_without_panicking() {
    for len in [0usize, 4, 12, 23, 25] {
        let encrypted = EncryptedKey {
            nonce: synthetic_nonce(len),
            salt: krusty_kms_crypto::random_bytes::<16>().to_vec(), // nonce rejected first
            encrypted_key: vec![0u8; 48],
        };
        let err = decrypt_private_key(&encrypted, &test_password(0), TEST_SCRYPT_N)
            .expect_err("must be rejected");
        assert!(
            format!("{err}").contains("Invalid nonce length"),
            "len={len}, got {err}"
        );
    }
}

#[test]
fn correct_nonce_length_is_accepted() {
    // Guards against over-tightening: a well-formed 24-byte nonce must
    // still reach the AEAD and fail on authentication, not on length.
    let payload = EncryptedPayload {
        nonce: synthetic_nonce(XNONCE_LEN),
        ciphertext: vec![0u8; 48],
    };
    let err = decrypt_with_key(&payload, &test_key(0)).expect_err("tag must fail");
    assert!(format!("{err}").contains("Decryption failed"), "got {err}");
}

fn test_password(offset: u8) -> String {
    (0..12)
        .map(|index| char::from(b'a' + index + offset))
        .collect()
}

fn synthetic_nonce(len: usize) -> Vec<u8> {
    krusty_kms_crypto::random_bytes::<64>()[..len].to_vec()
}

fn test_key(offset: u8) -> [u8; 32] {
    std::array::from_fn(|index| index as u8 + offset)
}

#[test]
fn encrypt_decrypt_private_key_roundtrip() {
    let private_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let password = test_password(0);

    let encrypted = encrypt_private_key(private_key, &password, TEST_SCRYPT_N).unwrap();
    assert_eq!(encrypted.nonce.len(), 24);
    assert_eq!(encrypted.salt.len(), 16);

    let decrypted = decrypt_private_key(&encrypted, &password, TEST_SCRYPT_N).unwrap();
    assert_eq!(decrypted, private_key);
}

#[test]
fn encrypt_decrypt_private_key_with_0x_prefix() {
    let private_key = "0xdeadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233";
    let password = test_password(0);

    let encrypted = encrypt_private_key(private_key, &password, TEST_SCRYPT_N).unwrap();
    let decrypted = decrypt_private_key(&encrypted, &password, TEST_SCRYPT_N).unwrap();
    // Decrypted is returned without 0x prefix
    assert_eq!(
        decrypted,
        "deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233"
    );
}

#[test]
fn wrong_password_fails_decryption() {
    let private_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let password = test_password(0);

    let encrypted = encrypt_private_key(private_key, &password, TEST_SCRYPT_N).unwrap();

    let wrong_password = test_password(1);
    let result = decrypt_private_key(&encrypted, &wrong_password, TEST_SCRYPT_N);
    assert!(result.is_err());
}

#[test]
fn reject_invalid_scrypt_n() {
    assert!(scrypt_log_n(1023).is_err());
    assert!(scrypt_log_n(3).is_err());
    assert!(scrypt_log_n(1 << 21).is_err());
    assert_eq!(scrypt_log_n(1024).unwrap(), 10);
}

#[test]
fn direct_encryption_rejects_oversized_hex_before_kdf() {
    let oversized = "a".repeat(MAX_DIRECT_KEY_BYTES * 2 + 1);
    let err = encrypt_private_key(&oversized, &test_password(0), TEST_SCRYPT_N)
        .expect_err("oversized key must be rejected before KDF");
    assert!(format!("{err}").contains("private key exceeds"));
}

#[test]
fn encrypt_decrypt_with_key_roundtrip() {
    let plaintext = b"some secret data that must remain confidential";
    let key = test_key(0);

    let payload = encrypt_with_key(plaintext, &key).unwrap();
    assert_eq!(payload.nonce.len(), 24);

    let decrypted = decrypt_with_key(&payload, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn wrong_key_fails_decrypt_with_key() {
    let plaintext = b"secret";
    let key = test_key(0);
    let wrong_key = test_key(1);

    let payload = encrypt_with_key(plaintext, &key).unwrap();

    let result = decrypt_with_key(&payload, &wrong_key);
    assert!(result.is_err());
}
