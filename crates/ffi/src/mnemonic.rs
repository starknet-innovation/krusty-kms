//! Mnemonic generation / validation FFI functions.

use std::ffi::c_char;
use std::panic::catch_unwind;
use std::slice;

use crate::error::*;
use crate::helpers::*;

#[no_mangle]
pub unsafe extern "C" fn kms_generate_mnemonic(
    word_count: u32,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(
        || match krusty_kms::generate_mnemonic(word_count as usize) {
            Ok(m) => write_string_output(&m, out, out_len, out_written),
            Err(_) => KMS_ERR_INVALID_INPUT,
        },
    )
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_generate_mnemonic_from_entropy(
    entropy: *const u8,
    entropy_len: usize,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        if entropy.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        let data = slice::from_raw_parts(entropy, entropy_len);
        match bip39::Mnemonic::from_entropy(data) {
            Ok(m) => {
                let s = m.to_string();
                write_string_output(&s, out, out_len, out_written)
            }
            Err(_) => KMS_ERR_INVALID_INPUT,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_validate_mnemonic(phrase: *const c_char) -> i32 {
    catch_unwind(|| {
        let s = match read_cstr(phrase) {
            Ok(s) => s,
            Err(e) => return e,
        };
        match krusty_kms::validate_mnemonic(s) {
            Ok(()) => KMS_OK,
            Err(_) => KMS_ERR_INVALID_INPUT,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_mnemonic_to_seed(
    phrase: *const c_char,
    passphrase: *const c_char,
    out: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let mnemonic_str = match read_cstr(phrase) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let pass_str = match read_cstr_optional(passphrase) {
            Ok(s) => s,
            Err(e) => return e,
        };

        match krusty_kms::mnemonic_to_seed(mnemonic_str, pass_str) {
            Ok(seed) => write_bytes_output(&seed, out, out_len, out_written),
            Err(_) => KMS_ERR_INVALID_INPUT,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}
