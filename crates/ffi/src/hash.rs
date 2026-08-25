//! Hash function FFI exports (Pedersen, Poseidon).

use std::panic::catch_unwind;
use std::slice;

use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};

use crate::error::*;
use crate::helpers::{felt_to_kms, kms_slice_to_felts, kms_to_felt, KMS_MAX_POSEIDON_VALUES};
use crate::types::*;

#[no_mangle]
pub unsafe extern "C" fn kms_pedersen_hash(
    left: *const KmsFelt,
    right: *const KmsFelt,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        if left.is_null() || right.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        let Ok(l) = kms_to_felt(&*left) else {
            return InvalidInput.to_status();
        };
        let Ok(r) = kms_to_felt(&*right) else {
            return InvalidInput.to_status();
        };
        let h = Pedersen::hash(&l, &r);
        *out = felt_to_kms(&h);
        KMS_OK
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_poseidon_hash_many(
    values: *const KmsFelt,
    values_len: usize,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        if out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        if values_len > KMS_MAX_POSEIDON_VALUES {
            return KMS_ERR_INVALID_INPUT;
        }
        if values_len > 0 && values.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let felts: Vec<Felt> = if values_len == 0 {
            vec![]
        } else {
            let kms_felts = slice::from_raw_parts(values, values_len);
            let Ok(felts) = kms_slice_to_felts(kms_felts) else {
                return InvalidInput.to_status();
            };
            felts
        };

        let h = krusty_kms_crypto::poseidon_hash_many(&felts);
        *out = felt_to_kms(&h);
        KMS_OK
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_rejects_oversized_values_len() {
        let mut out = KmsFelt { bytes: [0; 32] };
        let rc = unsafe {
            kms_poseidon_hash_many(std::ptr::null(), KMS_MAX_POSEIDON_VALUES + 1, &mut out)
        };
        assert_eq!(rc, KMS_ERR_INVALID_INPUT);
    }
}
