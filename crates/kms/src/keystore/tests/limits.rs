//! Malformed and resource-exhausting keystore metadata is rejected before
//! any KDF work and without panicking.

use super::*;

// Malformed keystore metadata must not panic.

/// Build a v1 keystore with an arbitrary `nonce`, bypassing `encrypt_keystore`.
fn keystore_v1_with_nonce_hex(nonce_hex: &str) -> String {
    serde_json::json!({
        "version": 1,
        "crypto": {
            "cipher": "xchacha20-poly1305",
            "kdf": "scrypt",
            "kdfparams": {
                "n": TEST_SCRYPT_N, "r": 8, "p": 1, "dklen": 32,
                "salt": hex::encode([0xabu8; 16]),
            },
            "nonce": nonce_hex,
            "ciphertext": hex::encode([0x11u8; 48]),
        }
    })
    .to_string()
}

/// Build a v3 keystore with an arbitrary `dklen` and IV length.
fn ethers_keystore_with(dklen: u64, iv_len: usize) -> String {
    serde_json::json!({
        "version": 3,
        "crypto": {
            "cipher": "aes-128-ctr",
            "kdf": "scrypt",
            "kdfparams": {
                "n": TEST_SCRYPT_N, "r": 8, "p": 1, "dklen": dklen,
                "salt": hex::encode([0xabu8; 32]),
            },
            "cipherparams": { "iv": hex::encode(vec![0xcdu8; iv_len]) },
            "ciphertext": hex::encode([0x11u8; 32]),
            "mac": "00",
        }
    })
    .to_string()
}

#[test]
fn decrypt_keystore_rejects_bad_nonce_length_without_panicking() {
    // 4 bytes instead of 24 used to hit an assert inside `generic-array`.
    for nonce_hex in ["", "deadbeef", &hex::encode([0u8; 25])] {
        let err = decrypt_keystore(&keystore_v1_with_nonce_hex(nonce_hex), &test_password(0))
            .expect_err("must be rejected");
        // The variant matters as much as the message: a wrong-length nonce is a
        // property of the file, and `CryptoError` would tell a caller to retry the
        // password. Same variant as every other malformed-field rejection here.
        assert!(
            matches!(err, KmsError::DeserializationError(ref m) if m.contains("Invalid nonce length")),
            "nonce {nonce_hex:?}, got {err:?}"
        );
    }
}

#[test]
fn decrypt_ethers_keystore_rejects_short_dklen_without_panicking() {
    // 10..=31 is the exact panic window: scrypt allows 10..=64, but anything
    // under 32 makes `derived_key[16..32]` go out of bounds.
    for dklen in [10u64, 15, 16, 17, 31] {
        let err = decrypt_ethers_keystore(&ethers_keystore_with(dklen, 16), &test_password(0))
            .expect_err("must be rejected");
        assert!(
            matches!(err, KmsError::DeserializationError(_)),
            "dklen={dklen}, got {err:?}"
        );
    }
}

#[test]
fn decrypt_ethers_keystore_rejects_bad_iv_length_without_panicking() {
    // IV length is validated before KDF/cipher init. Assert on the message, not
    // just `is_err`, so the case cannot pass for an unrelated reason.
    for iv_len in [0usize, 8, 15, 17, 32] {
        let err = decrypt_ethers_keystore(&ethers_keystore_with(32, iv_len), &test_password(0))
            .expect_err("must be rejected");
        assert!(
            format!("{err}").contains("Invalid cipherparams.iv length"),
            "iv_len={iv_len}, got {err}"
        );
    }
}

#[test]
fn well_formed_dklen_and_iv_reach_mac_verification() {
    // Guards against over-tightening: dklen=32 with a 16-byte IV must get
    // past the new length checks and fail on the MAC instead.
    let err = decrypt_ethers_keystore(&ethers_keystore_with(32, 16), &test_password(0))
        .expect_err("MAC must fail");
    assert!(
        format!("{err}").contains("MAC verification failed"),
        "got {err}"
    );
}

#[test]
fn decrypt_ethers_keystore_accepts_oversized_dklen() {
    // 33..=64 never panicked -- the slices stay in bounds and the extra bytes
    // are ignored, which is what geth and ethers do. Still accepted.
    for dklen in [33u64, 48, 64] {
        let err = decrypt_ethers_keystore(&ethers_keystore_with(dklen, 16), &test_password(0))
            .expect_err("MAC must fail");
        assert!(
            format!("{err}").contains("MAC verification failed"),
            "dklen={dklen}, got {err}"
        );
    }
}

#[test]
fn decrypt_ethers_keystore_rejects_resource_exhausting_params() {
    assert!(validate_scrypt_resource_params(TEST_SCRYPT_N, 8, 1, 32).is_ok());
    assert!(validate_scrypt_resource_params(TEST_SCRYPT_N, SCRYPT_R_MAX + 1, 1, 32).is_err());
    assert!(validate_scrypt_resource_params(TEST_SCRYPT_N, 8, SCRYPT_P_MAX + 1, 32).is_err());
    assert!(validate_scrypt_resource_params(TEST_SCRYPT_N, 8, 1, SCRYPT_DKLEN_MAX + 1).is_err());
    // dklen < 32 must be rejected: decryption indexes derived_key[16..32].
    assert!(validate_scrypt_resource_params(TEST_SCRYPT_N, 8, 1, SCRYPT_DKLEN_MIN - 1).is_err());
    // N=2^20 with r=32 exceeds the 256 MiB memory ceiling.
    assert!(validate_scrypt_resource_params(1 << 20, 32, 1, 32).is_err());
}

fn ethers_keystore_with_dklen(dklen: u64) -> String {
    let keystore = serde_json::json!({
        "version": 3,
        "crypto": {
            "cipher": "aes-128-ctr",
            "kdf": "scrypt",
            "kdfparams": {
                "n": TEST_SCRYPT_N,
                "r": 8,
                "p": 1,
                "dklen": dklen,
                "salt": hex::encode([0xab; 32]),
            },
            "cipherparams": { "iv": hex::encode([0xcd; 16]) },
            "ciphertext": hex::encode([0u8; 32]),
            "mac": hex::encode([0u8; 32]),
        }
    });
    serde_json::to_string(&keystore).unwrap()
}

#[test]
fn decrypt_ethers_keystore_rejects_dklen_below_32() {
    // A crafted keystore with dklen < 32 must return an error instead of
    // panicking on derived_key[16..32].
    let keystore_json = ethers_keystore_with_dklen(16);
    let result = decrypt_ethers_keystore(&keystore_json, &test_password(0));
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("dklen"), "unexpected error: {err_msg}");
}

#[test]
fn decrypt_ethers_keystore_rejects_truncating_dklen() {
    // 2^32 + 32 truncates to 32 under `as usize` on wasm32; the checked
    // conversion must reject it before the range validation runs.
    let keystore_json = ethers_keystore_with_dklen((1u64 << 32) + 32);
    let result = decrypt_ethers_keystore(&keystore_json, &test_password(0));
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("dklen"), "unexpected error: {err_msg}");
}

// Audit 2026-11-04, M-1: bounds that must hold before any scrypt work.

/// Build a v1 keystore with arbitrary scrypt `n` and salt, bypassing `encrypt_keystore`.
fn keystore_v1_with(n: u64, salt: &[u8]) -> String {
    serde_json::json!({
        "version": 1,
        "crypto": {
            "cipher": "xchacha20-poly1305",
            "kdf": "scrypt",
            "kdfparams": { "n": n, "r": 8, "p": 1, "dklen": 32, "salt": hex::encode(salt) },
            "nonce": hex::encode([0xcdu8; 24]),
            "ciphertext": hex::encode([0x11u8; 48]),
        }
    })
    .to_string()
}

/// Build a v3 keystore with an arbitrary salt.
fn ethers_keystore_with_salt(salt: &[u8]) -> String {
    serde_json::json!({
        "version": 3,
        "crypto": {
            "cipher": "aes-128-ctr",
            "kdf": "scrypt",
            "kdfparams": {
                "n": TEST_SCRYPT_N, "r": 8, "p": 1, "dklen": 32, "salt": hex::encode(salt),
            },
            "cipherparams": { "iv": hex::encode([0xcdu8; 16]) },
            "ciphertext": hex::encode([0x11u8; 32]),
            "mac": hex::encode([0u8; 32]),
        }
    })
    .to_string()
}

#[test]
fn decrypt_keystore_rejects_oversized_scrypt_n_before_kdf() {
    // n = 2^20 is a valid `scrypt_log_n` input, and with the native format's
    // fixed r = 8 it asks scrypt for 1 GiB before the password is checked.
    // The memory ceiling has to reject it as a property of the file, not as a
    // failed decryption after the allocation.
    let n = 1u64 << 20;
    assert!(scrypt_log_n(n as u32).is_ok());
    let err = decrypt_keystore(&keystore_v1_with(n, &[0xab; 16]), &test_password(0))
        .expect_err("must be rejected");
    assert!(
        matches!(err, KmsError::DeserializationError(ref m) if m.contains("ceiling")),
        "got {err:?}"
    );
}

#[test]
fn decrypt_keystore_rejects_oversized_salt_on_both_formats() {
    let salt = vec![0xab; MAX_KEYSTORE_SALT_BYTES + 1];
    let v1 = decrypt_keystore(
        &keystore_v1_with(TEST_SCRYPT_N.into(), &salt),
        &test_password(0),
    )
    .expect_err("v1 must be rejected");
    assert!(
        matches!(v1, KmsError::DeserializationError(ref m) if m.contains("salt")),
        "v1 got {v1:?}"
    );
    let v3 = decrypt_ethers_keystore(&ethers_keystore_with_salt(&salt), &test_password(0))
        .expect_err("v3 must be rejected");
    assert!(
        matches!(v3, KmsError::DeserializationError(ref m) if m.contains("salt")),
        "v3 got {v3:?}"
    );
}

#[test]
fn maximum_salt_still_reaches_the_kdf() {
    // Guards against over-tightening: a salt at the cap passes the length
    // check and fails on the password-dependent step instead.
    let salt = vec![0xab; MAX_KEYSTORE_SALT_BYTES];
    let v1 = decrypt_keystore(
        &keystore_v1_with(TEST_SCRYPT_N.into(), &salt),
        &test_password(0),
    )
    .expect_err("ciphertext is garbage");
    assert!(format!("{v1}").contains("Decryption failed"), "v1 got {v1}");
    let v3 = decrypt_ethers_keystore(&ethers_keystore_with_salt(&salt), &test_password(0))
        .expect_err("mac is garbage");
    assert!(
        format!("{v3}").contains("MAC verification failed"),
        "v3 got {v3}"
    );
}
