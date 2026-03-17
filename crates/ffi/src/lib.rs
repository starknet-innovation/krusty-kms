//! C ABI shared library for Krusty KMS.
//!
//! Produces `libkms.{so,dylib,dll}` implementing the full FFI surface consumed
//! by language wrapper packages (Go, Python, Swift, Rust, JVM, C, Dart,
//! TypeScript).
//!
//! # Safety
//!
//! All public `extern "C"` functions in this crate accept raw pointers from C
//! callers. The caller must ensure that:
//! - Non-NULL pointers point to valid, aligned, initialised memory of the
//!   correct type.
//! - Output buffers are at least as large as documented.
//! - Strings are valid NUL-terminated UTF-8.
//!
//! Every FFI entry point is wrapped in `catch_unwind` so that Rust panics
//! never propagate across the C ABI boundary.

#![allow(clippy::missing_safety_doc)] // safety is documented crate-wide above

// ---------------------------------------------------------------------------
// Domain modules
// ---------------------------------------------------------------------------

pub mod account;
pub mod address;
pub mod calldata;
pub mod coin_type;
pub mod derivation;
pub mod elgamal_ffi;
pub mod error;
pub mod felt;
pub mod handle;
pub mod hash;
pub mod helpers;
pub mod json_types;
pub mod mnemonic;
pub mod point;
pub mod proof;
pub mod signing;
pub mod types;

// ---------------------------------------------------------------------------
// ABI version
// ---------------------------------------------------------------------------

const ABI_MAJOR: u32 = 2;
const ABI_MINOR: u32 = 0;

// ---------------------------------------------------------------------------
// Re-export types for downstream use
// ---------------------------------------------------------------------------

pub use error::*;
pub use types::*;

// ---------------------------------------------------------------------------
// Version / ABI (2 functions)
// ---------------------------------------------------------------------------

use std::ffi::c_char;
use std::panic::catch_unwind;

#[no_mangle]
pub unsafe extern "C" fn kms_get_abi_version(major: *mut u32, minor: *mut u32) -> i32 {
    catch_unwind(|| {
        if major.is_null() || minor.is_null() {
            return error::KMS_ERR_NULL_POINTER;
        }
        *major = ABI_MAJOR;
        *minor = ABI_MINOR;
        error::KMS_OK
    })
    .unwrap_or(error::KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_get_version_string(
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let version = env!("CARGO_PKG_VERSION");
        helpers::write_string_output(version, out, out_len, out_written)
    })
    .unwrap_or(error::KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_types_core::felt::Felt;
    use std::ffi::CStr;

    #[test]
    fn test_felt_conversion_roundtrip() {
        let felt = Felt::from(42u64);
        let kms = helpers::felt_to_kms(&felt);
        let back = helpers::kms_to_felt(&kms);
        assert_eq!(felt, back);
    }

    #[test]
    fn test_projective_conversion_roundtrip() {
        let point = krusty_kms_crypto::StarkCurve::generator();
        let kms = helpers::proj_to_kms(&point);
        let back = helpers::kms_to_proj(&kms).unwrap();

        let a1 = krusty_kms_crypto::StarkCurve::projective_to_affine(&point).unwrap();
        let a2 = krusty_kms_crypto::StarkCurve::projective_to_affine(&back).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_error_name_valid() {
        unsafe {
            let name = error::kms_error_name(0);
            assert!(!name.is_null());
            let s = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(s, "KMS_OK");
        }
    }

    #[test]
    fn test_error_name_invalid() {
        unsafe {
            let name = error::kms_error_name(999);
            assert!(!name.is_null());
            let s = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(s, "KMS_ERR_INTERNAL");
        }
    }

    #[test]
    fn test_error_message_valid() {
        unsafe {
            let msg = error::kms_error_message(1);
            assert!(!msg.is_null());
            let s = CStr::from_ptr(msg).to_str().unwrap();
            assert_eq!(s, "null pointer argument");
        }
    }

    #[test]
    fn test_new_error_codes() {
        unsafe {
            let name = error::kms_error_name(KMS_ERR_INVALID_HANDLE);
            let s = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(s, "KMS_ERR_INVALID_HANDLE");

            let name = error::kms_error_name(KMS_ERR_JSON);
            let s = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(s, "KMS_ERR_JSON");
        }
    }

    #[test]
    fn test_coin_types() {
        assert_eq!(coin_type::kms_get_coin_type_tongo(), 5454);
        assert_eq!(coin_type::kms_get_coin_type_starknet(), 9004);
        assert_eq!(coin_type::kms_get_coin_type_nostr(), 1237);
    }

    #[test]
    fn test_abi_version() {
        let mut major = 0u32;
        let mut minor = 0u32;
        let rc = unsafe { kms_get_abi_version(&mut major, &mut minor) };
        assert_eq!(rc, KMS_OK);
        assert_eq!(major, 2);
        assert_eq!(minor, 0);
    }

    #[test]
    fn test_version_string() {
        let mut written = 0usize;
        let rc = unsafe { kms_get_version_string(std::ptr::null_mut(), 0, &mut written) };
        assert_eq!(rc, KMS_OK);
        assert!(written > 0);

        let mut buf = vec![0u8; written + 1];
        let rc = unsafe {
            kms_get_version_string(buf.as_mut_ptr() as *mut c_char, buf.len(), &mut written)
        };
        assert_eq!(rc, KMS_OK);
        let s = std::str::from_utf8(&buf[..written]).unwrap();
        assert!(!s.is_empty());
    }

    #[test]
    fn test_felt_hex_roundtrip() {
        let hex = std::ffi::CString::new("0x2a").unwrap();
        let mut felt = KmsFelt { bytes: [0; 32] };
        let rc = unsafe { felt::kms_felt_from_hex(hex.as_ptr(), &mut felt) };
        assert_eq!(rc, KMS_OK);

        let mut written = 0usize;
        let rc = unsafe { felt::kms_felt_to_hex(&felt, std::ptr::null_mut(), 0, &mut written) };
        assert_eq!(rc, KMS_OK);

        let mut buf = vec![0u8; written + 1];
        let rc = unsafe {
            felt::kms_felt_to_hex(
                &felt,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut written,
            )
        };
        assert_eq!(rc, KMS_OK);
        let s = std::str::from_utf8(&buf[..written]).unwrap();
        assert_eq!(
            s,
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );
    }

    #[test]
    fn test_felt_bytes_roundtrip() {
        let input: [u8; 1] = [42];
        let mut felt = KmsFelt { bytes: [0; 32] };
        let rc = unsafe { felt::kms_felt_from_bytes_be(input.as_ptr(), input.len(), &mut felt) };
        assert_eq!(rc, KMS_OK);

        let mut out = [0u8; 32];
        let mut written = 0usize;
        let rc =
            unsafe { felt::kms_felt_to_bytes_be(&felt, out.as_mut_ptr(), out.len(), &mut written) };
        assert_eq!(rc, KMS_OK);
        assert_eq!(written, 32);
        assert_eq!(out[31], 42);
    }

    #[test]
    fn test_pedersen_hash() {
        let a = helpers::felt_to_kms(&Felt::from(1u64));
        let b = helpers::felt_to_kms(&Felt::from(2u64));
        let mut out = KmsFelt { bytes: [0; 32] };
        let rc = unsafe { hash::kms_pedersen_hash(&a, &b, &mut out) };
        assert_eq!(rc, KMS_OK);
        assert_ne!(out.bytes, [0; 32]);
    }

    #[test]
    fn test_null_pointer_errors() {
        let rc = unsafe { kms_get_abi_version(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(rc, KMS_ERR_NULL_POINTER);

        let rc = unsafe { felt::kms_felt_from_hex(std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(rc, KMS_ERR_NULL_POINTER);
    }
}
