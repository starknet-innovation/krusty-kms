//! The `extern "C"` layer.
//!
//! Compiled **only for Android and iOS**. Nothing else consumes this ABI, and
//! gating it here means a desktop or CI build of the workspace exports no
//! symbols from this crate at all — the logic underneath is still compiled and
//! unit-tested on the host, which is where the tests in [`crate`] run.

#![cfg(any(target_os = "android", target_os = "ios"))]
#![allow(unsafe_code)] // this module is the raw-pointer C ABI boundary

use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::slice;

use crate::*;

/// Reads a caller-owned NUL-terminated UTF-8 string.
///
/// # Safety
/// `ptr` must be null or point to a NUL-terminated string valid for the call.
unsafe fn read_str<'a>(ptr: *const c_char) -> Result<&'a str, i32> {
    if ptr.is_null() {
        return Err(KMS_MOBILE_ERR_NULL_POINTER);
    }
    std::ffi::CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| KMS_MOBILE_ERR_INVALID_INPUT)
}

/// Reads a caller-owned byte buffer.
///
/// # Safety
/// `ptr` must be null or point to `len` readable bytes.
unsafe fn read_bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if ptr.is_null() {
        return Err(KMS_MOBILE_ERR_NULL_POINTER);
    }
    Ok(slice::from_raw_parts(ptr, len))
}

/// Writes `value` using the two-call sizing pattern: pass `out = NULL` to learn
/// the required length via `out_written`, then call again with a buffer.
///
/// # Safety
/// When `out` is non-null it must be writable for `out_len` bytes.
unsafe fn write_str(value: &str, out: *mut c_char, out_len: usize, out_written: *mut usize) -> i32 {
    let bytes = value.as_bytes();
    if !out_written.is_null() {
        *out_written = bytes.len();
    }
    if out.is_null() {
        return KMS_MOBILE_OK;
    }
    if out_len < bytes.len() + 1 {
        return KMS_MOBILE_ERR_BUFFER_TOO_SMALL;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, bytes.len());
    *(out.add(bytes.len()) as *mut u8) = 0;
    KMS_MOBILE_OK
}

/// Reports the ABI version. Bump the major on any breaking change to this file.
///
/// # Safety
/// `major` and `minor` must be writable or null.
#[no_mangle]
pub unsafe extern "C" fn kms_mobile_abi_version(major: *mut u32, minor: *mut u32) -> i32 {
    if major.is_null() || minor.is_null() {
        return KMS_MOBILE_ERR_NULL_POINTER;
    }
    *major = ABI_VERSION_MAJOR;
    *minor = ABI_VERSION_MINOR;
    KMS_MOBILE_OK
}

/// Static description of an error code. Never null, never freed by the caller.
#[no_mangle]
pub extern "C" fn kms_mobile_error_message(code: i32) -> *const c_char {
    // Every arm of `error_message` is a literal, so appending a NUL byte and
    // handing out the pointer is sound for the lifetime of the process.
    match code {
        KMS_MOBILE_OK => c"ok".as_ptr(),
        KMS_MOBILE_ERR_NULL_POINTER => c"a required pointer was null".as_ptr(),
        KMS_MOBILE_ERR_INVALID_INPUT => c"input was malformed or the wrong length".as_ptr(),
        KMS_MOBILE_ERR_BUFFER_TOO_SMALL => {
            c"output buffer too small; call with out=NULL to size it".as_ptr()
        }
        KMS_MOBILE_ERR_CRYPTO => c"the cryptographic operation failed".as_ptr(),
        KMS_MOBILE_ERR_INTERNAL => c"internal error".as_ptr(),
        KMS_MOBILE_ERR_VERIFY_FAILED => c"the signature did not verify against this key".as_ptr(),
        _ => c"unknown error code".as_ptr(),
    }
}

/// Poseidon commitment to the packed form of an ML-DSA-65 public key.
///
/// # Safety
/// `public_key` must point to `public_key_len` readable bytes; `out` must be
/// writable for `out_len` bytes or null.
#[no_mangle]
pub unsafe extern "C" fn kms_mobile_ml_dsa_key_commitment(
    public_key: *const u8,
    public_key_len: usize,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let key = match read_bytes(public_key, public_key_len) {
            Ok(k) => k,
            Err(e) => return e,
        };
        match key_commitment(key) {
            Ok(hex) => write_str(&hex, out, out_len, out_written),
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_MOBILE_ERR_INTERNAL)
}

/// Counterfactual account address for an ML-DSA-65 public key.
///
/// # Safety
/// `public_key` must point to `public_key_len` readable bytes; `class_hash` and
/// `salt` must be NUL-terminated; `out` must be writable for `out_len` bytes or
/// null.
#[no_mangle]
pub unsafe extern "C" fn kms_mobile_ml_dsa_account_address(
    public_key: *const u8,
    public_key_len: usize,
    class_hash: *const c_char,
    salt: *const c_char,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let key = match read_bytes(public_key, public_key_len) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let class_hash = match read_str(class_hash) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let salt = match read_str(salt) {
            Ok(s) => s,
            Err(e) => return e,
        };
        match account_address(key, class_hash, salt) {
            Ok(hex) => write_str(&hex, out, out_len, out_written),
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_MOBILE_ERR_INTERNAL)
}

/// Verifies a device's own signature against its own public key.
///
/// Returns `KMS_MOBILE_OK` when valid and `KMS_MOBILE_ERR_VERIFY_FAILED` when
/// not, so a caller can branch on one value rather than interpret a bool.
///
/// # Safety
/// Each pointer must point to the stated number of readable bytes.
#[no_mangle]
pub unsafe extern "C" fn kms_mobile_ml_dsa_verify(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    catch_unwind(|| {
        let key = match read_bytes(public_key, public_key_len) {
            Ok(k) => k,
            Err(e) => return e,
        };
        let message = match read_bytes(message, message_len) {
            Ok(m) => m,
            Err(e) => return e,
        };
        let signature = match read_bytes(signature, signature_len) {
            Ok(s) => s,
            Err(e) => return e,
        };
        match verify(key, message, signature) {
            Ok(()) => KMS_MOBILE_OK,
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_MOBILE_ERR_INTERNAL)
}
