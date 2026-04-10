//! Contract address computation FFI functions.

use std::panic::catch_unwind;
use std::slice;

use starknet_types_core::felt::Felt;

use crate::error::*;
use crate::helpers::*;
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
        if constructor_calldata_len > 0 && constructor_calldata.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let s = kms_to_felt(&*salt);
        let ch = kms_to_felt(&*class_hash);
        let da = kms_to_felt(&*deployer_address);

        let calldata: Vec<Felt> = if constructor_calldata_len == 0 {
            vec![]
        } else {
            let kms_cd = slice::from_raw_parts(constructor_calldata, constructor_calldata_len);
            kms_cd.iter().map(kms_to_felt).collect()
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

        let pk = kms_to_felt(&*public_key_x);
        let ch = kms_to_felt(&*class_hash);
        let s = if salt.is_null() {
            None
        } else {
            Some(kms_to_felt(&*salt))
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
