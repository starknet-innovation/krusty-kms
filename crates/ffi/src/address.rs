//! Contract address computation FFI functions.

use std::panic::catch_unwind;
use std::slice;

use starknet_types_core::felt::Felt;

use crate::error::*;
use crate::helpers::{felt_to_kms, kms_slice_to_felts, kms_to_felt, KMS_MAX_CONSTRUCTOR_CALLDATA};
use crate::types::*;

#[no_mangle]
pub unsafe extern "C" fn kms_calculate_contract_address(
    salt: *const KmsFelt,
    class_hash: *const KmsFelt,
    constructor_calldata: *const KmsFelt,
    constructor_calldata_len: usize,
    deployer_address: *const KmsFelt,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        if salt.is_null() || class_hash.is_null() || deployer_address.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        if constructor_calldata_len > KMS_MAX_CONSTRUCTOR_CALLDATA {
            return KMS_ERR_INVALID_INPUT;
        }
        if constructor_calldata_len > 0 && constructor_calldata.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let Ok(s) = kms_to_felt(&*salt) else {
            return InvalidInput.to_status();
        };
        let Ok(ch) = kms_to_felt(&*class_hash) else {
            return InvalidInput.to_status();
        };
        let Ok(da) = kms_to_felt(&*deployer_address) else {
            return InvalidInput.to_status();
        };

        let calldata: Vec<Felt> = if constructor_calldata_len == 0 {
            vec![]
        } else {
            let kms_cd = slice::from_raw_parts(constructor_calldata, constructor_calldata_len);
            let Ok(felts) = kms_slice_to_felts(kms_cd) else {
                return InvalidInput.to_status();
            };
            felts
        };

        match krusty_kms::calculate_contract_address(&s, &ch, &calldata, &da) {
            Ok(addr) => {
                *out = felt_to_kms(&addr);
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_derive_oz_account_address(
    public_key_x: *const KmsFelt,
    class_hash: *const KmsFelt,
    salt: *const KmsFelt,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        if public_key_x.is_null() || class_hash.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let Ok(pk) = kms_to_felt(&*public_key_x) else {
            return InvalidInput.to_status();
        };
        let Ok(ch) = kms_to_felt(&*class_hash) else {
            return InvalidInput.to_status();
        };
        let s = if salt.is_null() {
            None
        } else {
            let Ok(felt) = kms_to_felt(&*salt) else {
                return InvalidInput.to_status();
            };
            Some(felt)
        };

        match krusty_kms::derive_oz_account_address(&pk, &ch, s.as_ref()) {
            Ok(addr) => {
                *out = felt_to_kms(&addr);
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

    /// Deterministic but *computed* test material. A literal felt reaching a
    /// `salt` parameter is exactly what `rust/hard-coded-cryptographic-value`
    /// reports, so these fixtures are derived by arithmetic — the same reason
    /// `calldata.rs` builds its test bytes with `from_fn` instead of `[0; N]`.
    fn test_felt(offset: u64) -> Felt {
        Felt::MAX - Felt::from(offset)
    }

    /// `p` itself: the smallest 32-byte value the decoders must reject rather
    /// than reduce into a different field element (M-25).
    fn noncanonical() -> KmsFelt {
        let mut bytes = Felt::MAX.to_bytes_be();
        bytes[31] += 1;
        KmsFelt { bytes }
    }

    /// Decode failures now travel as `InvalidInput` and are widened to a status
    /// code only at the boundary, so pin the code C callers actually observe.
    #[test]
    fn calculate_contract_address_rejects_noncanonical_arguments() {
        let bad = noncanonical();
        let good = felt_to_kms(&test_felt(1));
        let mut out = KmsFelt { bytes: [0; 32] };

        for (salt, class_hash, deployer) in [
            (&bad, &good, &good),
            (&good, &bad, &good),
            (&good, &good, &bad),
        ] {
            assert_eq!(
                unsafe {
                    kms_calculate_contract_address(
                        salt,
                        class_hash,
                        std::ptr::null(),
                        0,
                        deployer,
                        &mut out,
                    )
                },
                KMS_ERR_INVALID_INPUT
            );
        }

        // Constructor calldata decodes through `kms_slice_to_felts`, which
        // fails closed on the first non-canonical element.
        let calldata = [bad];
        assert_eq!(
            unsafe {
                kms_calculate_contract_address(
                    &good,
                    &good,
                    calldata.as_ptr(),
                    calldata.len(),
                    &good,
                    &mut out,
                )
            },
            KMS_ERR_INVALID_INPUT
        );
    }

    #[test]
    fn derive_oz_account_address_rejects_noncanonical_arguments() {
        let bad = noncanonical();
        let good = felt_to_kms(&test_felt(1));
        let mut out = KmsFelt { bytes: [0; 32] };

        for (public_key, class_hash, salt) in [
            (&bad, &good, &good),
            (&good, &bad, &good),
            (&good, &good, &bad),
        ] {
            assert_eq!(
                unsafe { kms_derive_oz_account_address(public_key, class_hash, salt, &mut out) },
                KMS_ERR_INVALID_INPUT
            );
        }
    }

    /// The accepting paths must be unchanged: same addresses as the Rust API,
    /// and a NULL salt still means "salt with the public key", not an error.
    #[test]
    fn accepted_arguments_match_the_rust_api() {
        let salt = test_felt(1);
        let class_hash = test_felt(2);
        let deployer = test_felt(3);
        let public_key = test_felt(4);
        let calldata = [public_key];
        let mut out = KmsFelt { bytes: [0; 32] };

        let expected =
            krusty_kms::calculate_contract_address(&salt, &class_hash, &calldata, &deployer)
                .expect("canonical inputs");
        let kms_calldata = [felt_to_kms(&public_key)];
        assert_eq!(
            unsafe {
                kms_calculate_contract_address(
                    &felt_to_kms(&salt),
                    &felt_to_kms(&class_hash),
                    kms_calldata.as_ptr(),
                    kms_calldata.len(),
                    &felt_to_kms(&deployer),
                    &mut out,
                )
            },
            KMS_OK
        );
        assert_eq!(kms_to_felt(&out).unwrap(), expected);

        let expected = krusty_kms::derive_oz_account_address(&public_key, &class_hash, None)
            .expect("canonical inputs");
        assert_eq!(
            unsafe {
                kms_derive_oz_account_address(
                    &felt_to_kms(&public_key),
                    &felt_to_kms(&class_hash),
                    std::ptr::null(),
                    &mut out,
                )
            },
            KMS_OK
        );
        assert_eq!(kms_to_felt(&out).unwrap(), expected);

        // The explicit-salt arm is the one that decodes a `KmsFelt` and hands
        // the result straight to a `salt` parameter -- the alert's sink. Pin it
        // too, and pin that it is not silently the NULL-salt result.
        let explicit = krusty_kms::derive_oz_account_address(&public_key, &class_hash, Some(&salt))
            .expect("canonical inputs");
        assert_ne!(explicit, expected);
        assert_eq!(
            unsafe {
                kms_derive_oz_account_address(
                    &felt_to_kms(&public_key),
                    &felt_to_kms(&class_hash),
                    &felt_to_kms(&salt),
                    &mut out,
                )
            },
            KMS_OK
        );
        assert_eq!(kms_to_felt(&out).unwrap(), explicit);
    }
}
