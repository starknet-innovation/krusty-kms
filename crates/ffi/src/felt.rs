//! Felt conversion FFI functions.

use std::ffi::c_char;
use std::panic::catch_unwind;
use std::slice;

use starknet_types_core::felt::Felt;

use crate::error::*;
use crate::helpers::*;
use crate::types::*;

#[no_mangle]
pub unsafe extern "C" fn kms_felt_from_hex(hex: *const c_char, out: *mut KmsFelt) -> i32 {
    catch_unwind(|| {
        let s = match read_cstr(hex) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let trimmed = s.strip_prefix("0x").unwrap_or(s);
        if trimmed.is_empty() || trimmed.len() > 64 {
            return KMS_ERR_INVALID_INPUT;
        }
        if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return KMS_ERR_INVALID_INPUT;
        }

        let felt = Felt::from_hex_unchecked(s);
        *out = felt_to_kms(&felt);
        KMS_OK
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_felt_to_hex(
    value: *const KmsFelt,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        if value.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        let felt = kms_to_felt(&*value);
        let hex = format!("0x{:064x}", felt);
        write_string_output(&hex, out, out_len, out_written)
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_felt_from_bytes_be(
    bytes: *const u8,
    bytes_len: usize,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        if bytes.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        if bytes_len == 0 || bytes_len > 32 {
            return KMS_ERR_INVALID_INPUT;
        }
        let data = slice::from_raw_parts(bytes, bytes_len);
        let felt = Felt::from_bytes_be_slice(data);
        *out = felt_to_kms(&felt);
        KMS_OK
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_felt_to_bytes_be(
    value: *const KmsFelt,
    out: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        if value.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        let felt = kms_to_felt(&*value);
        let bytes = felt.to_bytes_be();
        write_bytes_output(&bytes, out, out_len, out_written)
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}
