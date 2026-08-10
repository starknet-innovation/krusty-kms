//! Signing FFI functions (Stark ECDSA + Ethereum secp256k1).

use std::panic::catch_unwind;
use std::slice;

use krusty_kms_common::SecretFelt;
use zeroize::Zeroize;

use crate::error::*;
use crate::helpers::*;
use crate::types::*;

// ---------------------------------------------------------------------------
// Stark ECDSA
// ---------------------------------------------------------------------------

/// Sign a message hash with a Stark private key (ECDSA on Stark curve).
///
/// Produces `(r, s)` as two `KmsFelt` outputs.
/// Uses deterministic RFC-6979 nonce generation (cairo-compatible seed retry).
#[no_mangle]
pub unsafe extern "C" fn kms_stark_sign(
    hash: *const KmsFelt,
    private_key: *const KmsFelt,
    out_r: *mut KmsFelt,
    out_s: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        if hash.is_null() || private_key.is_null() || out_r.is_null() || out_s.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let msg = kms_to_felt(&*hash);
        // SecretFelt zeroizes on drop (volatile write); plain assignment can be DCE'd.
        let sk = SecretFelt::new(kms_to_felt(&*private_key));

        match krusty_kms::sign_stark_hash(sk.expose_secret(), &msg) {
            Ok(sig) => {
                *out_r = felt_to_kms(&sig.r);
                *out_s = felt_to_kms(&sig.s);
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Ethereum secp256k1
// ---------------------------------------------------------------------------

/// Sign a hash with a secp256k1 private key, producing the 5-felt OZ
/// signature format `[r_low, r_high, s_low, s_high, v]`.
///
/// `eth_private_key_bytes` must point to exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn kms_eth_sign(
    hash: *const KmsFelt,
    eth_private_key_bytes: *const u8,
    out_signature: *mut KmsEthSignature,
) -> i32 {
    catch_unwind(|| {
        if hash.is_null() || eth_private_key_bytes.is_null() || out_signature.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let h = kms_to_felt(&*hash);
        let pk_slice = slice::from_raw_parts(eth_private_key_bytes, 32);
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(pk_slice);

        let signer = match krusty_kms::EthSigner::from_private_key(&pk_arr) {
            Ok(s) => s,
            Err(_) => {
                pk_arr.zeroize();
                return KMS_ERR_INVALID_INPUT;
            }
        };

        // Guaranteed wipe of the temporary private-key copy.
        pk_arr.zeroize();

        match signer.sign_hash(&h) {
            Ok(sig) => {
                *out_signature = KmsEthSignature {
                    r_low: felt_to_kms(&sig[0]),
                    r_high: felt_to_kms(&sig[1]),
                    s_low: felt_to_kms(&sig[2]),
                    s_high: felt_to_kms(&sig[3]),
                    v: felt_to_kms(&sig[4]),
                };
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_types_core::felt::Felt;

    #[test]
    fn test_stark_sign() {
        let hash = felt_to_kms(&Felt::from(0x1234u64));
        let sk = felt_to_kms(&Felt::from(42u64));
        let mut r = KmsFelt { bytes: [0; 32] };
        let mut s = KmsFelt { bytes: [0; 32] };

        // SAFETY: all pointers reference initialized `KmsFelt` values; `r` and
        // `s` are writable output storage for the duration of the call.
        let rc = unsafe { kms_stark_sign(&hash, &sk, &mut r, &mut s) };
        assert_eq!(rc, KMS_OK);
        // r and s should be non-zero
        assert_ne!(r.bytes, [0; 32]);
        assert_ne!(s.bytes, [0; 32]);
    }

    #[test]
    fn test_stark_sign_is_deterministic() {
        let hash = felt_to_kms(&Felt::from(0x1234u64));
        let sk = felt_to_kms(&Felt::from(42u64));
        let mut r1 = KmsFelt { bytes: [0; 32] };
        let mut s1 = KmsFelt { bytes: [0; 32] };
        let mut r2 = KmsFelt { bytes: [0; 32] };
        let mut s2 = KmsFelt { bytes: [0; 32] };

        // SAFETY: all pointers reference initialized `KmsFelt` values; `r1`/`s1`
        // and `r2`/`s2` are distinct writable outputs for each call.
        let rc1 = unsafe { kms_stark_sign(&hash, &sk, &mut r1, &mut s1) };
        let rc2 = unsafe { kms_stark_sign(&hash, &sk, &mut r2, &mut s2) };
        assert_eq!(rc1, KMS_OK);
        assert_eq!(rc2, KMS_OK);
        assert_eq!(r1.bytes, r2.bytes);
        assert_eq!(s1.bytes, s2.bytes);
    }

    #[test]
    fn test_eth_sign() {
        let hash = felt_to_kms(&Felt::from(0x1234u64));
        // A well-known test private key
        let pk_bytes =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        let mut sig = KmsEthSignature {
            r_low: KmsFelt { bytes: [0; 32] },
            r_high: KmsFelt { bytes: [0; 32] },
            s_low: KmsFelt { bytes: [0; 32] },
            s_high: KmsFelt { bytes: [0; 32] },
            v: KmsFelt { bytes: [0; 32] },
        };

        // SAFETY: `hash` is an initialized `KmsFelt`; `pk_bytes` is a 32-byte
        // buffer as the callee requires; `sig` is writable output storage.
        let rc = unsafe { kms_eth_sign(&hash, pk_bytes.as_ptr(), &mut sig) };
        assert_eq!(rc, KMS_OK);
    }

    #[test]
    fn test_stark_sign_null_pointers() {
        let hash = felt_to_kms(&Felt::from(42u64));
        let sk = felt_to_kms(&Felt::from(42u64));
        let mut r = KmsFelt { bytes: [0; 32] };

        // SAFETY: `hash`, `sk`, and `r` reference initialized `KmsFelt`
        // values; the null `s` is the case under test and the callee checks
        // for null before dereferencing.
        let rc = unsafe { kms_stark_sign(&hash, &sk, &mut r, std::ptr::null_mut()) };
        assert_eq!(rc, KMS_ERR_NULL_POINTER);
    }

    #[test]
    fn test_stark_sign_zero_key_returns_error_not_panic() {
        // The zero key hits the identity point inside the public-key
        // derivation; the FFI boundary must return an error, never unwind.
        let hash = felt_to_kms(&Felt::from(0x1234u64));
        let zero = felt_to_kms(&Felt::ZERO);
        let mut r = KmsFelt { bytes: [0; 32] };
        let mut s = KmsFelt { bytes: [0; 32] };

        // SAFETY: all pointers reference initialized `KmsFelt` values; `r` and
        // `s` are writable output storage for the duration of the call.
        let rc = unsafe { kms_stark_sign(&hash, &zero, &mut r, &mut s) };
        assert_eq!(rc, KMS_ERR_CRYPTO);
    }
}
