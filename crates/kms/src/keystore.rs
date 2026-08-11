//! Keystore encryption format and ethers.js keystore migration.
//!
//! This module provides:
//! - A krusty-kms native keystore format (version 1, XChaCha20-Poly1305 + scrypt)
//! - Decryption of ethers.js / Web3 Secret Storage keystores (version 3, AES-128-CTR + scrypt)

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use krusty_kms_common::{KmsError, Result};
use scrypt::{scrypt, Params as ScryptParams};
use sha3::{Digest, Keccak256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::encryption::{
    decrypt_with_key, derive_scrypt_key, encrypt_with_key, scrypt_log_n, xnonce,
};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// Derived-key length required by the Web3 Secret Storage v3 format.
const V3_DKLEN: usize = 32;

/// AES-128-CTR IV length required by the Web3 Secret Storage v3 format.
const V3_IV_LEN: usize = 16;

fn parse_u32_kdf_param(value: Option<u64>, field: &str) -> Result<u32> {
    let n = value
        .ok_or_else(|| KmsError::DeserializationError(format!("Missing kdfparams.{field}")))?;
    u32::try_from(n).map_err(|_| {
        KmsError::DeserializationError(format!("kdfparams.{field} exceeds u32 range (got {n})"))
    })
}

// Checked u64 -> usize conversion: a plain `as usize` truncates on wasm32, so
// e.g. 2^32 + 32 would become 32 and bypass the dklen ceiling below.
fn parse_usize_kdf_param(value: Option<u64>, field: &str) -> Result<usize> {
    let n = value
        .ok_or_else(|| KmsError::DeserializationError(format!("Missing kdfparams.{field}")))?;
    usize::try_from(n).map_err(|_| {
        KmsError::DeserializationError(format!("kdfparams.{field} exceeds usize range (got {n})"))
    })
}

/// Ethereum-keystore-compatible ceilings for attacker-controlled scrypt params.
///
/// Memory ≈ 128 · N · r bytes. With [`scrypt_log_n`]'s N ≤ 2^20 and r ≤ 32 that
/// caps at ~4 GiB; we additionally reject products that would exceed 256 MiB so
/// malicious keystores cannot turn import into a DoS.
const SCRYPT_R_MAX: u32 = 32;
const SCRYPT_P_MAX: u32 = 16;
// Decryption unconditionally splits the derived key at [..16] and [16..32],
// so anything shorter than 32 bytes would panic instead of erroring.
const SCRYPT_DKLEN_MIN: usize = 32;
const SCRYPT_DKLEN_MAX: usize = 64;
const SCRYPT_MEMORY_CEILING_BYTES: u64 = 256 * 1024 * 1024;

fn validate_scrypt_resource_params(n: u32, r: u32, p: u32, dklen: usize) -> Result<()> {
    let _log_n = scrypt_log_n(n)?;
    if !(1..=SCRYPT_R_MAX).contains(&r) {
        return Err(KmsError::DeserializationError(format!(
            "kdfparams.r={r} outside allowed range 1..={SCRYPT_R_MAX}"
        )));
    }
    if !(1..=SCRYPT_P_MAX).contains(&p) {
        return Err(KmsError::DeserializationError(format!(
            "kdfparams.p={p} outside allowed range 1..={SCRYPT_P_MAX}"
        )));
    }
    if !(SCRYPT_DKLEN_MIN..=SCRYPT_DKLEN_MAX).contains(&dklen) {
        return Err(KmsError::DeserializationError(format!(
            "kdfparams.dklen={dklen} outside allowed range {SCRYPT_DKLEN_MIN}..={SCRYPT_DKLEN_MAX}"
        )));
    }
    // scrypt memory ≈ 128 * N * r
    let memory = (n as u64).saturating_mul(r as u64).saturating_mul(128);
    if memory > SCRYPT_MEMORY_CEILING_BYTES {
        return Err(KmsError::DeserializationError(format!(
            "scrypt params request ~{memory} bytes of memory (ceiling {SCRYPT_MEMORY_CEILING_BYTES})"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Native keystore (version 1)
// ---------------------------------------------------------------------------

/// Encrypt a mnemonic into a JSON keystore string.
///
/// The resulting JSON has the form:
/// ```json
/// {
///   "version": 1,
///   "crypto": {
///     "cipher": "xchacha20-poly1305",
///     "kdf": "scrypt",
///     "kdfparams": { "n": 32768, "r": 8, "p": 1, "dklen": 32, "salt": "hex..." },
///     "nonce": "hex...",
///     "ciphertext": "hex..."
///   }
/// }
/// ```
///
/// # Arguments
/// * `mnemonic` - The mnemonic phrase to encrypt
/// * `password` - User-supplied password
/// * `scrypt_n` - Scrypt cost parameter N (must be a power of 2)
pub fn encrypt_keystore(mnemonic: &str, password: &str, scrypt_n: u32) -> Result<String> {
    // Generate 16-byte salt
    let salt = krusty_kms_crypto::random_bytes::<16>();

    // Derive encryption key
    let key = derive_scrypt_key(password.as_bytes(), &salt, scrypt_n)?;

    // Encrypt mnemonic bytes
    let payload = encrypt_with_key(mnemonic.as_bytes(), &key)?;

    // Build JSON
    let keystore = serde_json::json!({
        "version": 1,
        "crypto": {
            "cipher": "xchacha20-poly1305",
            "kdf": "scrypt",
            "kdfparams": {
                "n": scrypt_n,
                "r": 8,
                "p": 1,
                "dklen": 32,
                "salt": hex::encode(salt),
            },
            "nonce": hex::encode(&payload.nonce),
            "ciphertext": hex::encode(&payload.ciphertext),
        }
    });

    serde_json::to_string(&keystore)
        .map_err(|e| KmsError::SerializationError(format!("Failed to serialize keystore: {e}")))
}

/// Decrypt a native krusty-kms keystore (version 1) to recover the mnemonic.
///
/// # Arguments
/// * `keystore_json` - JSON keystore string produced by [`encrypt_keystore`]
/// * `password` - The password used during encryption
pub fn decrypt_keystore(keystore_json: &str, password: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(keystore_json)
        .map_err(|e| KmsError::DeserializationError(format!("Invalid keystore JSON: {e}")))?;

    let version = v["version"]
        .as_u64()
        .ok_or_else(|| KmsError::DeserializationError("Missing version field".to_string()))?;
    if version != 1 {
        return Err(KmsError::DeserializationError(format!(
            "Unsupported keystore version: {version}"
        )));
    }

    let crypto = &v["crypto"];

    let salt = hex::decode(
        crypto["kdfparams"]["salt"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing salt".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid salt hex: {e}")))?;

    let n = parse_u32_kdf_param(crypto["kdfparams"]["n"].as_u64(), "n")?;

    let nonce = hex::decode(
        crypto["nonce"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing nonce".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid nonce hex: {e}")))?;

    let ciphertext = hex::decode(
        crypto["ciphertext"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing ciphertext".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid ciphertext hex: {e}")))?;

    // Validate before deriving, so a malformed nonce costs no KDF work.
    xnonce(&nonce)?;

    let key = derive_scrypt_key(password.as_bytes(), &salt, n)?;

    let payload = crate::encryption::EncryptedPayload { nonce, ciphertext };
    let plaintext = decrypt_with_key(&payload, &key)?;

    String::from_utf8(plaintext)
        .map_err(|e| KmsError::CryptoError(format!("Decrypted keystore is not valid UTF-8: {e}")))
}

// ---------------------------------------------------------------------------
// ethers.js / Web3 Secret Storage (version 3) migration
// ---------------------------------------------------------------------------

/// Decrypt an ethers.js / Web3 Secret Storage keystore (version 3, scrypt KDF).
///
/// Supports the standard format:
/// ```json
/// {
///   "version": 3,
///   "crypto": {
///     "cipher": "aes-128-ctr",
///     "kdf": "scrypt",
///     "kdfparams": { "n": N, "r": 8, "p": 1, "dklen": 32, "salt": "hex" },
///     "cipherparams": { "iv": "hex" },
///     "ciphertext": "hex",
///     "mac": "hex"
///   }
/// }
/// ```
///
/// # Arguments
/// * `keystore_json` - JSON keystore string in ethers.js format
/// * `password` - The password used during encryption
///
/// # Returns
/// The decrypted content as a hex-encoded string (typically a private key).
pub fn decrypt_ethers_keystore(keystore_json: &str, password: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(keystore_json)
        .map_err(|e| KmsError::DeserializationError(format!("Invalid keystore JSON: {e}")))?;

    let version = v["version"]
        .as_u64()
        .ok_or_else(|| KmsError::DeserializationError("Missing version field".to_string()))?;
    if version != 3 {
        return Err(KmsError::DeserializationError(format!(
            "Expected ethers keystore version 3, got {version}"
        )));
    }

    let crypto = &v["crypto"];

    let kdf = crypto["kdf"]
        .as_str()
        .ok_or_else(|| KmsError::DeserializationError("Missing kdf field".to_string()))?;
    if kdf != "scrypt" {
        return Err(KmsError::DeserializationError(format!(
            "Unsupported KDF: {kdf} (only scrypt is supported)"
        )));
    }

    // Parse kdfparams
    let salt = hex::decode(
        crypto["kdfparams"]["salt"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing salt".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid salt hex: {e}")))?;

    let n = parse_u32_kdf_param(crypto["kdfparams"]["n"].as_u64(), "n")?;

    let r = parse_u32_kdf_param(crypto["kdfparams"]["r"].as_u64(), "r")?;

    let p = parse_u32_kdf_param(crypto["kdfparams"]["p"].as_u64(), "p")?;

    let dklen = parse_usize_kdf_param(crypto["kdfparams"]["dklen"].as_u64(), "dklen")?;

    validate_scrypt_resource_params(n, r, p, dklen)?;

    // Parse cipher params
    let iv =
        hex::decode(crypto["cipherparams"]["iv"].as_str().ok_or_else(|| {
            KmsError::DeserializationError("Missing cipherparams.iv".to_string())
        })?)
        .map_err(|e| KmsError::DeserializationError(format!("Invalid IV hex: {e}")))?;

    let mut ciphertext = hex::decode(
        crypto["ciphertext"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing ciphertext".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid ciphertext hex: {e}")))?;

    let expected_mac = hex::decode(
        crypto["mac"]
            .as_str()
            .ok_or_else(|| KmsError::DeserializationError("Missing mac".to_string()))?,
    )
    .map_err(|e| KmsError::DeserializationError(format!("Invalid mac hex: {e}")))?;

    // Validate IV length before KDF so a short IV yields a clear error instead of
    // failing later inside AES-128-CTR initialization.
    if iv.len() != V3_IV_LEN {
        return Err(KmsError::DeserializationError(format!(
            "Invalid cipherparams.iv length: expected {V3_IV_LEN} bytes, got {}",
            iv.len()
        )));
    }

    // Derive key via scrypt (N/r/p already resource-capped above)
    let log_n = scrypt_log_n(n)?;
    let params = ScryptParams::new(log_n, r, p)
        .map_err(|e| KmsError::CryptoError(format!("Invalid scrypt params: {e}")))?;
    let mut derived_key = Zeroizing::new(vec![0u8; dklen]);
    scrypt(password.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| KmsError::CryptoError(format!("Scrypt KDF failed: {e}")))?;

    let aes_key = &derived_key[..V3_DKLEN / 2];
    let mac_key = &derived_key[V3_DKLEN / 2..V3_DKLEN];

    // Verify MAC: Keccak256(mac_key || ciphertext). Streamed rather than concatenated
    // to avoid a second copy of the MAC key in a plain `Vec` sized by the file.
    let mut mac = Keccak256::new();
    mac.update(mac_key);
    mac.update(&ciphertext);
    let computed_mac = mac.finalize();

    // Constant-time MAC compare to avoid password-oracle timing leaks.
    if !bool::from(computed_mac.as_slice().ct_eq(expected_mac.as_slice())) {
        return Err(KmsError::CryptoError(
            "MAC verification failed: wrong password or corrupted keystore".to_string(),
        ));
    }

    // Decrypt with AES-128-CTR using the first 16 bytes of the derived key. `Zeroizing`
    // because this buffer becomes the private key in place -- the higher-value secret.
    let mut plaintext = Zeroizing::new(std::mem::take(&mut ciphertext));
    let mut stream =
        Aes128Ctr::new_from_slices(aes_key, &iv).expect("AES-128-CTR key/IV lengths validated");
    stream.apply_keystream(&mut plaintext);

    Ok(hex::encode(&*plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SCRYPT_N: u32 = 1024;

    fn test_password(offset: u8) -> String {
        (0..12)
            .map(|index| char::from(b'a' + index + offset))
            .collect()
    }

    #[test]
    fn encrypt_decrypt_keystore_roundtrip() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = test_password(0);

        let keystore_json = encrypt_keystore(mnemonic, &password, TEST_SCRYPT_N).unwrap();

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&keystore_json).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["crypto"]["cipher"], "xchacha20-poly1305");
        assert_eq!(parsed["crypto"]["kdf"], "scrypt");
        assert_eq!(parsed["crypto"]["kdfparams"]["n"], TEST_SCRYPT_N);

        let decrypted = decrypt_keystore(&keystore_json, &password).unwrap();
        assert_eq!(decrypted, mnemonic);
    }

    #[test]
    fn decrypt_keystore_wrong_password_fails() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = test_password(0);

        let keystore_json = encrypt_keystore(mnemonic, &password, TEST_SCRYPT_N).unwrap();

        let wrong_password = test_password(1);
        let result = decrypt_keystore(&keystore_json, &wrong_password);
        assert!(result.is_err());
    }

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
    fn decrypt_ethers_keystore_known_vector() {
        // Build a test keystore by manually encrypting a known private key
        // using the ethers.js format (AES-128-CTR + scrypt).
        let private_key_bytes =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe512961708279f696ae35e0c2a1b5ce")
                .unwrap();
        let password = test_password(0);
        // Deterministic salt and IV for the test vector
        let salt = vec![0xab; 32];
        let iv = vec![0xcd; 16];

        // Derive key
        let log_n = scrypt_log_n(TEST_SCRYPT_N).unwrap();
        let params = ScryptParams::new(log_n, 8, 1).unwrap();
        let mut derived_key = vec![0u8; 32];
        scrypt(password.as_bytes(), &salt, &params, &mut derived_key).unwrap();

        // Encrypt with AES-128-CTR
        let aes_key = &derived_key[..16];
        let mut ciphertext = private_key_bytes.clone();
        let mut cipher = Aes128Ctr::new_from_slices(aes_key, &iv).unwrap();
        cipher.apply_keystream(&mut ciphertext);

        // Compute MAC
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&derived_key[16..32]);
        mac_input.extend_from_slice(&ciphertext);
        let mac = Keccak256::digest(&mac_input);

        // Build keystore JSON
        let keystore = serde_json::json!({
            "version": 3,
            "crypto": {
                "cipher": "aes-128-ctr",
                "kdf": "scrypt",
                "kdfparams": {
                    "n": TEST_SCRYPT_N,
                    "r": 8,
                    "p": 1,
                    "dklen": 32,
                    "salt": hex::encode(&salt),
                },
                "cipherparams": {
                    "iv": hex::encode(&iv),
                },
                "ciphertext": hex::encode(&ciphertext),
                "mac": hex::encode(mac.as_slice()),
            }
        });

        let keystore_json = serde_json::to_string(&keystore).unwrap();

        // Decrypt and verify
        let decrypted = decrypt_ethers_keystore(&keystore_json, &password).unwrap();
        assert_eq!(
            decrypted,
            "4c0883a69102937d6231471b5dbb6204fe512961708279f696ae35e0c2a1b5ce"
        );
    }

    #[test]
    fn decrypt_ethers_keystore_wrong_password_fails() {
        // Minimal valid keystore with wrong password
        let salt = vec![0xab; 32];
        let iv = vec![0xcd; 16];
        let password = test_password(0);

        let log_n = scrypt_log_n(TEST_SCRYPT_N).unwrap();
        let params = ScryptParams::new(log_n, 8, 1).unwrap();
        let mut derived_key = vec![0u8; 32];
        scrypt(password.as_bytes(), &salt, &params, &mut derived_key).unwrap();

        let ciphertext = vec![0u8; 32];
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&derived_key[16..32]);
        mac_input.extend_from_slice(&ciphertext);
        let mac = Keccak256::digest(&mac_input);

        let keystore = serde_json::json!({
            "version": 3,
            "crypto": {
                "cipher": "aes-128-ctr",
                "kdf": "scrypt",
                "kdfparams": {
                    "n": TEST_SCRYPT_N,
                    "r": 8,
                    "p": 1,
                    "dklen": 32,
                    "salt": hex::encode(&salt),
                },
                "cipherparams": { "iv": hex::encode(&iv) },
                "ciphertext": hex::encode(&ciphertext),
                "mac": hex::encode(mac.as_slice()),
            }
        });

        let keystore_json = serde_json::to_string(&keystore).unwrap();

        let wrong_password = test_password(1);
        let result = decrypt_ethers_keystore(&keystore_json, &wrong_password);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("MAC verification failed"));
    }

    #[test]
    fn decrypt_ethers_keystore_rejects_resource_exhausting_params() {
        assert!(validate_scrypt_resource_params(TEST_SCRYPT_N, 8, 1, 32).is_ok());
        assert!(validate_scrypt_resource_params(TEST_SCRYPT_N, SCRYPT_R_MAX + 1, 1, 32).is_err());
        assert!(validate_scrypt_resource_params(TEST_SCRYPT_N, 8, SCRYPT_P_MAX + 1, 32).is_err());
        assert!(
            validate_scrypt_resource_params(TEST_SCRYPT_N, 8, 1, SCRYPT_DKLEN_MAX + 1).is_err()
        );
        // dklen < 32 must be rejected: decryption indexes derived_key[16..32].
        assert!(
            validate_scrypt_resource_params(TEST_SCRYPT_N, 8, 1, SCRYPT_DKLEN_MIN - 1).is_err()
        );
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
}
