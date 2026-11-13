//! Password KDF parameters shared by direct encryption and keystore import.

use krusty_kms_common::{KmsError, Result};
use scrypt::{scrypt, Params as ScryptParams};
use zeroize::Zeroizing;

/// Minimum allowed scrypt N (2^10).
const SCRYPT_N_MIN: u32 = 1 << 10;
/// Maximum allowed scrypt N (2^20). Memory budgets may reject lower values.
const SCRYPT_N_MAX: u32 = 1 << 20;
/// Shared upper bound for memory requested by a password-based KDF.
pub(crate) const SCRYPT_MEMORY_CEILING_BYTES: u64 = 256 * 1024 * 1024;
/// Largest scrypt N for the default direct-key budget (fixed r=8, p=1).
pub const DEFAULT_SCRYPT_N_MAX: u32 = (SCRYPT_MEMORY_CEILING_BYTES / (8 * 128)) as u32;
/// Largest salt accepted by a direct password-based operation.
const MAX_DIRECT_SCRYPT_SALT_BYTES: usize = 128;

/// Reject malformed caller-owned direct fields before spending KDF resources.
pub(super) fn ensure_direct_input_lengths(encrypted: &super::EncryptedKey) -> Result<()> {
    if encrypted.salt.len() != 16 {
        return Err(KmsError::DeserializationError(format!(
            "Invalid direct-key salt length: expected 16 bytes, got {}",
            encrypted.salt.len()
        )));
    }
    let len = encrypted.encrypted_key.len();
    if !(16..=super::MAX_DIRECT_KEY_BYTES + 16).contains(&len) {
        return Err(KmsError::DeserializationError(format!(
            "encrypted key length {len} outside 16..={} bytes",
            super::MAX_DIRECT_KEY_BYTES + 16
        )));
    }
    Ok(())
}

/// Validate scrypt N and return `log2(N)` for [`ScryptParams`].
pub(crate) fn scrypt_log_n(n: u32) -> Result<u8> {
    if !(SCRYPT_N_MIN..=SCRYPT_N_MAX).contains(&n) || !n.is_power_of_two() {
        return Err(KmsError::CryptoError(format!(
            "Invalid scrypt N={n}: must be a power of 2 in [{SCRYPT_N_MIN}, {SCRYPT_N_MAX}]"
        )));
    }
    Ok(n.trailing_zeros() as u8)
}

/// Default budget for newly encrypted keys and callers handling untrusted
/// ciphertext metadata. Legacy decryption may deliberately exceed it.
pub(crate) fn ensure_default_scrypt_budget(n: u32) -> Result<()> {
    scrypt_log_n(n)?;
    // Direct operations use fixed r=8 and p=1.
    if n > DEFAULT_SCRYPT_N_MAX {
        return Err(KmsError::CryptoError(format!(
            "scrypt N={n} exceeds the {SCRYPT_MEMORY_CEILING_BYTES} byte memory ceiling"
        )));
    }
    Ok(())
}

/// Derive a wiped 32-byte key. The caller chooses whether to enforce the
/// default memory budget; old ciphertexts can still request the legacy range.
pub(crate) fn derive_scrypt_key(
    password: &[u8],
    kdf_salt: &[u8],
    n: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let log_n = scrypt_log_n(n)?;
    if kdf_salt.len() > MAX_DIRECT_SCRYPT_SALT_BYTES {
        return Err(KmsError::CryptoError(format!(
            "scrypt salt exceeds the {MAX_DIRECT_SCRYPT_SALT_BYTES} byte limit"
        )));
    }
    let params = ScryptParams::new(log_n, 8, 1)
        .map_err(|e| KmsError::CryptoError(format!("Invalid scrypt params: {e}")))?;
    let mut key = Zeroizing::new([u8::default(); 32]);
    scrypt(password, kdf_salt, &params, &mut *key)
        .map_err(|e| KmsError::CryptoError(format!("Scrypt KDF failed: {e}")))?;
    Ok(key)
}
