//! Scrypt KDF with wiped ROMix scratch.
//!
//! This follows the portable implementation in RustCrypto `scrypt` 0.12.0,
//! licensed MIT OR Apache-2.0. The locked crate's KDF does not wipe its large
//! B/V/T buffers, so we keep ownership of those buffers here and wipe them on
//! every return path. The portable BlockMix is used because this crate forbids
//! the unsafe intrinsics in RustCrypto's SSE2/wasm SIMD variants.

use krusty_kms_common::{KmsError, Result};
use pbkdf2::pbkdf2_hmac;
use scrypt::Params;
use sha2::Sha256;
use zeroize::Zeroizing;

#[path = "scrypt_wiping/block_mix.rs"]
mod block_mix;
#[path = "scrypt_wiping/romix.rs"]
mod romix;

/// Derive bytes exactly as `scrypt::scrypt`, retaining ownership of all large
/// scratch allocations until their `Zeroizing` drop. Callers validate their
/// application-specific memory and work budgets before invoking this function.
pub(crate) fn scrypt(
    password: &[u8],
    salt: &[u8],
    params: &Params,
    output: &mut [u8],
) -> Result<()> {
    if output.is_empty() || output.len() / 32 > 0xffff_ffff {
        return Err(KmsError::CryptoError(
            "Invalid scrypt output length".to_string(),
        ));
    }

    let n = 1usize
        .checked_shl(u32::from(params.log_n()))
        .ok_or_else(|| KmsError::CryptoError("Invalid scrypt work size".to_string()))?;
    let r128 = (params.r() as usize)
        .checked_mul(128)
        .ok_or_else(|| KmsError::CryptoError("Invalid scrypt work size".to_string()))?;
    let pr128 = (params.p() as usize)
        .checked_mul(r128)
        .ok_or_else(|| KmsError::CryptoError("Invalid scrypt work size".to_string()))?;
    let nr128 = n
        .checked_mul(r128)
        .ok_or_else(|| KmsError::CryptoError("Invalid scrypt work size".to_string()))?;

    let mut b = Zeroizing::new(vec![0u8; pr128]);
    pbkdf2_hmac::<Sha256>(password, salt, 1, &mut b);

    let mut v = Zeroizing::new(vec![0u8; nr128]);
    let mut t = Zeroizing::new(vec![0u8; r128]);
    for chunk in b.chunks_mut(r128) {
        romix::scrypt_ro_mix(chunk, &mut v, &mut t, n);
    }

    pbkdf2_hmac::<Sha256>(password, &b, 1, output);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::scrypt::scrypt as upstream_scrypt;

    #[test]
    fn matches_locked_scrypt_across_parameters() {
        // Different salts/passwords, work factors, lane counts and output
        // lengths guard keystore compatibility with the locked implementation.
        for (log_n, r, p, password, salt, output_len) in [
            (4, 1, 1, b"".as_slice(), b"".as_slice(), 64),
            (8, 2, 2, b"password".as_slice(), b"NaCl".as_slice(), 32),
            (
                10,
                8,
                1,
                b"synthetic-password".as_slice(),
                b"salt-16-bytes----".as_slice(),
                64,
            ),
            (
                10,
                1,
                3,
                b"p\0ass".as_slice(),
                b"salt\0bytes".as_slice(),
                32,
            ),
        ] {
            let params = Params::new(log_n, r, p).unwrap();
            let mut expected = vec![0u8; output_len];
            let mut actual = vec![0u8; output_len];
            upstream_scrypt(password, salt, &params, &mut expected).unwrap();
            scrypt(password, salt, &params, &mut actual).unwrap();
            assert_eq!(actual, expected, "log_n={log_n}, r={r}, p={p}");
        }
    }
}
