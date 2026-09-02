//! Mnemonic generation / validation FFI functions.

use std::ffi::c_char;
use std::panic::catch_unwind;
use std::slice;

use zeroize::Zeroizing;

use crate::error::*;
use crate::helpers::{
    read_cstr, read_cstr_optional, write_bytes_output, write_string_output, KMS_MAX_ENTROPY_LEN,
};

#[no_mangle]
pub unsafe extern "C" fn kms_generate_mnemonic(
    word_count: u32,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(
        || match krusty_kms::generate_mnemonic(word_count as usize) {
            // Mnemonic is secret key material: zeroize the Rust-side copy on drop.
            Ok(m) => write_string_output(&Zeroizing::new(m), out, out_len, out_written),
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
        if entropy_len == 0 || entropy_len > KMS_MAX_ENTROPY_LEN {
            return KMS_ERR_INVALID_INPUT;
        }
        let data = slice::from_raw_parts(entropy, entropy_len);
        match bip39::Mnemonic::from_entropy(data) {
            Ok(m) => {
                // The parsed word indices and the phrase are both secret key
                // material: zeroize every Rust-side copy on drop.
                let m = Zeroizing::new(m);
                let s = Zeroizing::new(m.to_string());
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
            // Seed is the root of every derived key: zeroize the Rust-side copy.
            Ok(seed) => write_bytes_output(&Zeroizing::new(seed)[..], out, out_len, out_written),
            Err(_) => KMS_ERR_INVALID_INPUT,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_rejects_oversized_len() {
        let entropy = [0u8; KMS_MAX_ENTROPY_LEN + 1];
        let mut written = 0usize;
        let rc = unsafe {
            kms_generate_mnemonic_from_entropy(
                entropy.as_ptr(),
                entropy.len(),
                std::ptr::null_mut(),
                0,
                &mut written,
            )
        };
        assert_eq!(rc, KMS_ERR_INVALID_INPUT);
    }
}
