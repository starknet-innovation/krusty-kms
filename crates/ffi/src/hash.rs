//! Hash function FFI exports (Pedersen, Poseidon).

use std::panic::catch_unwind;
use std::slice;

use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};

use crate::error::*;
use crate::helpers::*;
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
        let l = kms_to_felt(&*left);
        let r = kms_to_felt(&*right);
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
        if values_len > 0 && values.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let felts: Vec<Felt> = if values_len == 0 {
            vec![]
        } else {
            let kms_felts = slice::from_raw_parts(values, values_len);
            kms_felts.iter().map(kms_to_felt).collect()
        };

        let h = krusty_kms_crypto::poseidon_hash_many(&felts);
        *out = felt_to_kms(&h);
        KMS_OK
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}
