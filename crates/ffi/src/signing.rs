//! Signing FFI functions (Stark ECDSA + Ethereum secp256k1).

use std::panic::catch_unwind;
use std::slice;

use crate::error::*;
use crate::helpers::*;
use crate::types::*;

// ---------------------------------------------------------------------------
// Stark ECDSA
// ---------------------------------------------------------------------------

/// Sign a message hash with a Stark private key (ECDSA on Stark curve).
///
/// Produces `(r, s)` as two `KmsFelt` outputs.
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
        let sk = kms_to_felt(&*private_key);

        // Generate a random nonce k
        let k = krusty_kms_crypto::scalar::random_felt();

        match starknet_crypto::sign(&sk, &msg, &k) {
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
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };

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

        let rc = unsafe { kms_stark_sign(&hash, &sk, &mut r, &mut s) };
        assert_eq!(rc, KMS_OK);
        // r and s should be non-zero
        assert_ne!(r.bytes, [0; 32]);
        assert_ne!(s.bytes, [0; 32]);
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

        let rc = unsafe { kms_eth_sign(&hash, pk_bytes.as_ptr(), &mut sig) };
        assert_eq!(rc, KMS_OK);
    }

    #[test]
    fn test_stark_sign_null_pointers() {
        let hash = felt_to_kms(&Felt::from(42u64));
        let sk = felt_to_kms(&Felt::from(42u64));
        let mut r = KmsFelt { bytes: [0; 32] };

        let rc = unsafe { kms_stark_sign(&hash, &sk, &mut r, std::ptr::null_mut()) };
        assert_eq!(rc, KMS_ERR_NULL_POINTER);
    }
}
