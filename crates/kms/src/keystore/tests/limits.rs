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
    let salt = krusty_kms_crypto::random_bytes::<16>();
    let err = decrypt_keystore(&keystore_v1_with(n, &salt), &test_password(0))
        .expect_err("must be rejected");
    assert!(
        matches!(err, KmsError::DeserializationError(ref m) if m.contains("ceiling")),
        "got {err:?}"
    );
}

#[test]
fn decrypt_keystore_rejects_oversized_salt_on_both_formats() {
    // Only the length matters; the bytes come from the OS so no fixed salt
    // is checked in.
    let salt = krusty_kms_crypto::random_bytes::<{ MAX_KEYSTORE_SALT_BYTES + 1 }>();
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
    let salt = krusty_kms_crypto::random_bytes::<MAX_KEYSTORE_SALT_BYTES>();
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

/// `encrypt_keystore` accepts exactly the `n` values `decrypt_keystore`
/// accepts, so the SDK never writes a keystore it cannot read back.
#[test]
fn encrypt_keystore_rejects_n_above_the_decrypt_ceiling() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    for n in [1u32 << 19, 1 << 20] {
        assert!(scrypt_log_n(n).is_ok(), "n={n} is a valid scrypt parameter");
        let err = encrypt_keystore(mnemonic, &test_password(0), n).expect_err("must be rejected");
        assert!(
            matches!(err, KmsError::DeserializationError(ref m) if m.contains("ceiling")),
            "n={n}, got {err:?}"
        );
    }
    // 2^18 · 8 · 128 bytes is exactly the ceiling: the largest accepted cost.
    assert!(validate_scrypt_resource_params(1 << 18, 8, 1, 32).is_ok());
}

#[test]
fn direct_encryption_rejects_scrypt_cost_above_keystore_ceiling() {
    // This is a valid scrypt N, but fixed r=8 would allocate 512 MiB.
    let err = crate::encryption::ensure_default_scrypt_budget(1 << 19)
        .expect_err("new encryption must reject the oversized request");
    assert!(format!("{err}").contains("memory ceiling"));
    // The old range remains parseable for deliberate legacy decryption; no
    // 512 MiB KDF is attempted in this test.
    assert!(scrypt_log_n(1 << 19).is_ok());
}

#[test]
fn direct_encryption_rejects_oversized_salt_before_kdf() {
    let salt = vec![0xabu8; 129];
    let err = derive_scrypt_key(b"synthetic-password", &salt, TEST_SCRYPT_N)
        .expect_err("direct KDF must reject an oversized salt");
    assert!(format!("{err}").contains("scrypt salt exceeds"));
}

#[test]
fn direct_decryption_rejects_oversized_ciphertext_before_kdf() {
    let encrypted = crate::encryption::EncryptedKey {
        nonce: vec![0; 24],
        salt: vec![0; 16],
        encrypted_key: vec![0; 1024 * 1024 + 1],
    };
    let err = crate::encryption::decrypt_private_key(&encrypted, "synthetic-password", 1 << 20)
        .expect_err("oversized ciphertext must be rejected before legacy KDF");
    assert!(format!("{err}").contains("encrypted key length"));
}

#[test]
fn direct_decryption_rejects_short_ciphertext_and_salt_before_kdf() {
    let mut encrypted = crate::encryption::EncryptedKey {
        nonce: vec![0; 24],
        salt: vec![0; 16],
        encrypted_key: vec![0; 15],
    };
    let err = crate::encryption::decrypt_private_key(&encrypted, "synthetic-password", 1 << 20)
        .expect_err("short AEAD tag must be rejected before KDF");
    assert!(format!("{err}").contains("encrypted key length"));

    encrypted.encrypted_key.push(0);
    encrypted.salt.pop();
    let err = crate::encryption::decrypt_private_key(&encrypted, "synthetic-password", 1 << 20)
        .expect_err("short direct-key salt must be rejected before KDF");
    assert!(format!("{err}").contains("direct-key salt length"));
}

#[test]
fn bounded_direct_decryption_rejects_legacy_high_n_before_kdf() {
    let encrypted = crate::encryption::EncryptedKey {
        nonce: vec![0; 24],
        salt: vec![0; 16],
        encrypted_key: vec![0; 48],
    };
    let err =
        crate::encryption::decrypt_private_key_bounded(&encrypted, "synthetic-password", 1 << 19)
            .expect_err("untrusted metadata must not trigger a 512 MiB KDF");
    assert!(format!("{err}").contains("memory ceiling"));
}

#[test]
fn imported_keystore_limits_total_scrypt_work() {
    // A small memory footprint can still hide many sequential ROMix lanes.
    assert!(validate_scrypt_resource_params(1 << 18, 8, 1, 32).is_ok());
    let err = validate_scrypt_resource_params(1 << 18, 1, 16, 32)
        .expect_err("excessive CPU work must be rejected");
    assert!(format!("{err}").contains("work units"));
}

#[test]
fn both_imports_reject_oversized_json_before_parsing() {
    // Invalid JSON would have a parse error if the cap were checked too late.
    let oversized = " ".repeat(MAX_KEYSTORE_JSON_BYTES + 1);
    for import in [
        decrypt_keystore as fn(&str, &str) -> Result<String>,
        decrypt_ethers_keystore,
    ] {
        let err = import(&oversized, "synthetic-password").expect_err("must reject");
        assert!(format!("{err}").contains("keystore JSON exceeds"));
    }
}

#[test]
fn native_keystore_never_writes_an_unimportable_large_mnemonic() {
    let oversized = "a".repeat(super::super::input_limits::MAX_NATIVE_MNEMONIC_BYTES + 1);
    let err = encrypt_keystore(&oversized, "synthetic-password", TEST_SCRYPT_N)
        .expect_err("large plaintext must be rejected before KDF");
    assert!(format!("{err}").contains("mnemonic exceeds"));
}

#[test]
fn salt_length_is_rejected_before_hex_decoding() {
    // The invalid hex would yield a different error if decoded first.
    let encoded = "z".repeat(MAX_KEYSTORE_SALT_BYTES * 2 + 1);
    let v1 = serde_json::json!({
        "version": 1,
        "crypto": {"kdfparams": {"salt": encoded}}
    })
    .to_string();
    let v3 = serde_json::json!({
        "version": 3,
        "crypto": {"kdf": "scrypt", "kdfparams": {"salt": encoded}}
    })
    .to_string();
    for (input, import) in [
        (
            v1.as_str(),
            decrypt_keystore as fn(&str, &str) -> Result<String>,
        ),
        (v3.as_str(), decrypt_ethers_keystore),
    ] {
        let err = import(input, "synthetic-password").expect_err("must reject");
        assert!(format!("{err}").contains("kdfparams.salt exceeds"));
    }
}
