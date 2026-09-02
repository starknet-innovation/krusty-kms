//! Minimal C ABI for the iOS and Android post-quantum signers.
//!
//! # Why this is not part of `crates/ffi`
//!
//! The canonical surface in `crates/ffi` exports mnemonic handling, BIP-39
//! derivation, software Stark signing and Tongo proof generation. A Rust
//! `staticlib` retains every `#[no_mangle]` symbol it defines, so linking that
//! crate into a phone would place *private-key derivation and software signing
//! inside a binary whose entire security story is that the key never leaves the
//! secure element*. That is an attack-surface argument, not a size one, and it
//! is why this crate exists separately.
//!
//! The rule this surface holds to is the same one the WASM ML-DSA exports state:
//! **it only ever handles public material.** There is no key generation and no
//! signing here, and there will not be — the enclave does both.
//!
//! # Shape
//!
//! Bytes in for key material, hex felts out, `i32` error codes, no structs. The
//! canonical header speaks hex because its consumer is TypeScript; this one
//! speaks bytes because its consumers hold `Data` and `ByteArray`, and hex round
//! trips at an ABI boundary are somewhere to lose a leading zero.
//!
//! The `extern "C"` layer lives in [`exports`] and is compiled **only for
//! Android and iOS**. Everything it calls lives here as ordinary Rust so the
//! logic is unit-tested on the host, where those targets cannot run.

// Denied here rather than allowed crate-wide: this module is ordinary Rust and
// should stay that way. Only the ABI shim in `exports` relaxes it.
#![deny(unsafe_code)]

use krusty_kms_crypto::ml_dsa::{ml_dsa_key_commitment, ml_dsa_verify};
use starknet_types_core::felt::Felt;

pub mod exports;

/// ML-DSA-65 public key length in bytes (FIPS 204).
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
/// ML-DSA-65 signature length in bytes (FIPS 204).
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;
/// A Starknet transaction hash, as the big-endian bytes that get signed.
pub const MESSAGE_BYTES: usize = 32;

pub const KMS_MOBILE_OK: i32 = 0;
pub const KMS_MOBILE_ERR_NULL_POINTER: i32 = 1;
pub const KMS_MOBILE_ERR_INVALID_INPUT: i32 = 2;
pub const KMS_MOBILE_ERR_BUFFER_TOO_SMALL: i32 = 3;
pub const KMS_MOBILE_ERR_CRYPTO: i32 = 4;
pub const KMS_MOBILE_ERR_INTERNAL: i32 = 5;
pub const KMS_MOBILE_ERR_VERIFY_FAILED: i32 = 6;

pub const ABI_VERSION_MAJOR: u32 = 1;
pub const ABI_VERSION_MINOR: u32 = 0;

/// Human-readable text for an error code. Never allocates; never null.
pub fn error_message(code: i32) -> &'static str {
    match code {
        KMS_MOBILE_OK => "ok",
        KMS_MOBILE_ERR_NULL_POINTER => "a required pointer was null",
        KMS_MOBILE_ERR_INVALID_INPUT => "input was malformed or the wrong length",
        KMS_MOBILE_ERR_BUFFER_TOO_SMALL => "output buffer too small; call with out=NULL to size it",
        KMS_MOBILE_ERR_CRYPTO => "the cryptographic operation failed",
        KMS_MOBILE_ERR_INTERNAL => "internal error",
        KMS_MOBILE_ERR_VERIFY_FAILED => "the signature did not verify against this key",
        _ => "unknown error code",
    }
}

/// Felts always cross this boundary zero-padded to 64 hex digits, so a caller
/// cannot accidentally produce a shorter spelling of the same value.
fn felt_hex(value: &Felt) -> String {
    format!("0x{value:064x}")
}

fn parse_felt(hex: &str) -> Result<Felt, i32> {
    let trimmed = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X"));
    let Some(body) = trimmed else {
        return Err(KMS_MOBILE_ERR_INVALID_INPUT);
    };
    if body.is_empty() || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KMS_MOBILE_ERR_INVALID_INPUT);
    }
    Felt::from_hex(hex).map_err(|_| KMS_MOBILE_ERR_INVALID_INPUT)
}

fn check_public_key(public_key: &[u8]) -> Result<(), i32> {
    if public_key.len() == ML_DSA_65_PUBLIC_KEY_BYTES {
        Ok(())
    } else {
        Err(KMS_MOBILE_ERR_INVALID_INPUT)
    }
}

/// Poseidon commitment to the 925-felt packed form of `public_key`.
///
/// This is the account contract's whole constructor argument, and the value the
/// contract recomputes on chain from the key each transaction carries.
pub fn key_commitment(public_key: &[u8]) -> Result<String, i32> {
    check_public_key(public_key)?;
    ml_dsa_key_commitment(public_key)
        .map(|felt| felt_hex(&felt))
        .map_err(|_| KMS_MOBILE_ERR_CRYPTO)
}

/// The counterfactual account address for `public_key`.
///
/// `salt` is a parameter rather than a baked constant deliberately: the wallet
/// currently deploys ML-DSA accounts at salt `0x0` (`ML_DSA_ADDRESS_SALT`), and
/// a constant duplicated here would be a second source of truth that could
/// drift silently. The deployer is always zero — these accounts are deployed by
/// `DEPLOY_ACCOUNT`, not by another contract.
pub fn account_address(public_key: &[u8], class_hash: &str, salt: &str) -> Result<String, i32> {
    check_public_key(public_key)?;
    let class_hash = parse_felt(class_hash)?;
    let salt = parse_felt(salt)?;
    let commitment = ml_dsa_key_commitment(public_key).map_err(|_| KMS_MOBILE_ERR_CRYPTO)?;
    krusty_kms::calculate_contract_address(&salt, &class_hash, &[commitment], &Felt::ZERO)
        .map(|felt| felt_hex(&felt))
        .map_err(|_| KMS_MOBILE_ERR_CRYPTO)
}

/// Does `signature` verify against `public_key` over `message`?
///
/// The phone's own sanity check, and the reason it is worth the ABI slot: a
/// device that returns a signature over a re-encoded key — Android Keystore
/// hands back X.509 DER, 1974 bytes, where CryptoKit hands back the raw 1952 —
/// fails here immediately and locally, instead of surfacing later as the wallet
/// refusing to broadcast for no visible reason.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), i32> {
    check_public_key(public_key)?;
    if message.len() != MESSAGE_BYTES || signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(KMS_MOBILE_ERR_INVALID_INPUT);
    }
    let mut bytes = [0u8; MESSAGE_BYTES];
    bytes.copy_from_slice(message);
    let hash = Felt::from_bytes_be(&bytes);
    if ml_dsa_verify(public_key, &hash, signature) {
        Ok(())
    } else {
        Err(KMS_MOBILE_ERR_VERIFY_FAILED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The exported symbols are Android/iOS only, so the host tests exercise the
    // layer underneath them. That is the whole reason the split exists.

    #[test]
    fn rejects_wrong_length_public_keys() {
        for len in [0, 1951, 1953, 1974] {
            assert_eq!(
                key_commitment(&vec![0u8; len]),
                Err(KMS_MOBILE_ERR_INVALID_INPUT)
            );
        }
    }

    #[test]
    fn rejects_a_der_wrapped_public_key() {
        // 1974 bytes is exactly what Android Keystore returns. Accepting it
        // would produce a commitment for a key nobody holds.
        assert_eq!(
            key_commitment(&vec![0u8; 1974]),
            Err(KMS_MOBILE_ERR_INVALID_INPUT)
        );
    }

    #[test]
    fn rejects_malformed_felts() {
        let key = vec![0u8; ML_DSA_65_PUBLIC_KEY_BYTES];
        for bad in ["", "0x", "1", "0xzz", "deadbeef"] {
            assert_eq!(
                account_address(&key, bad, "0x0"),
                Err(KMS_MOBILE_ERR_INVALID_INPUT),
                "class hash {bad:?}",
            );
            assert_eq!(
                account_address(&key, "0x1", bad),
                Err(KMS_MOBILE_ERR_INVALID_INPUT),
                "salt {bad:?}",
            );
        }
    }

    #[test]
    fn rejects_wrong_length_messages_and_signatures() {
        let key = vec![0u8; ML_DSA_65_PUBLIC_KEY_BYTES];
        let signature = vec![0u8; ML_DSA_65_SIGNATURE_BYTES];
        assert_eq!(
            verify(&key, &[0u8; 31], &signature),
            Err(KMS_MOBILE_ERR_INVALID_INPUT)
        );
        assert_eq!(
            verify(&key, &[0u8; 33], &signature),
            Err(KMS_MOBILE_ERR_INVALID_INPUT)
        );
        assert_eq!(
            verify(&key, &[0u8; 32], &vec![0u8; 3308]),
            Err(KMS_MOBILE_ERR_INVALID_INPUT)
        );
    }

    #[test]
    fn felts_are_always_fully_padded() {
        assert_eq!(felt_hex(&Felt::ZERO).len(), 66);
        assert_eq!(felt_hex(&Felt::ONE), format!("0x{:064x}", 1));
    }

    #[test]
    fn every_error_code_has_a_message() {
        for code in [
            KMS_MOBILE_OK,
            KMS_MOBILE_ERR_NULL_POINTER,
            KMS_MOBILE_ERR_INVALID_INPUT,
            KMS_MOBILE_ERR_BUFFER_TOO_SMALL,
            KMS_MOBILE_ERR_CRYPTO,
            KMS_MOBILE_ERR_INTERNAL,
            KMS_MOBILE_ERR_VERIFY_FAILED,
        ] {
            assert_ne!(error_message(code), "unknown error code");
        }
    }
}
