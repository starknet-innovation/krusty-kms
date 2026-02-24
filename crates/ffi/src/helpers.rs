//! Conversion helpers and output-buffer utilities.

use std::ffi::{c_char, CStr};

use starknet_types_core::curve::{AffinePoint, ProjectivePoint};
use starknet_types_core::felt::Felt;

use crate::error::*;
use crate::types::*;

// ---------------------------------------------------------------------------
// Felt <-> KmsFelt
// ---------------------------------------------------------------------------

pub fn felt_to_kms(f: &Felt) -> KmsFelt {
    KmsFelt {
        bytes: f.to_bytes_be(),
    }
}

pub fn kms_to_felt(k: &KmsFelt) -> Felt {
    Felt::from_bytes_be_slice(&k.bytes)
}

// ---------------------------------------------------------------------------
// Point <-> KmsProjectivePoint / KmsAffinePoint
// ---------------------------------------------------------------------------

pub fn proj_to_kms(p: &ProjectivePoint) -> KmsProjectivePoint {
    KmsProjectivePoint {
        x: felt_to_kms(&p.x()),
        y: felt_to_kms(&p.y()),
        z: felt_to_kms(&p.z()),
    }
}

pub fn kms_to_proj(k: &KmsProjectivePoint) -> ProjectivePoint {
    let x = kms_to_felt(&k.x);
    let y = kms_to_felt(&k.y);
    let z = kms_to_felt(&k.z);
    ProjectivePoint::new(x, y, z)
}

pub fn affine_to_kms(a: &AffinePoint) -> KmsAffinePoint {
    KmsAffinePoint {
        x: felt_to_kms(&a.x()),
        y: felt_to_kms(&a.y()),
    }
}

// ---------------------------------------------------------------------------
// String output helper (two-call pattern)
// ---------------------------------------------------------------------------

/// Write a string to the caller's buffer using the two-call pattern.
///
/// - If `out` is NULL: write the needed byte count (excluding NUL) to
///   `*out_written`, return OK.
/// - If `out` is non-NULL and `out_len` is sufficient: write string + NUL,
///   set `*out_written`.
/// - Otherwise: return `KMS_ERR_BUFFER_TOO_SMALL`.
pub unsafe fn write_string_output(
    s: &str,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    let bytes = s.as_bytes();
    let needed = bytes.len(); // excluding NUL

    if out.is_null() {
        if !out_written.is_null() {
            *out_written = needed;
        }
        return KMS_OK;
    }

    // Need space for string + NUL terminator
    if out_len < needed + 1 {
        if !out_written.is_null() {
            *out_written = needed;
        }
        return KMS_ERR_BUFFER_TOO_SMALL;
    }

    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, needed);
    *(out.add(needed) as *mut u8) = 0; // NUL terminator

    if !out_written.is_null() {
        *out_written = needed;
    }

    KMS_OK
}

/// Write raw bytes to the caller's buffer using the two-call pattern.
pub unsafe fn write_bytes_output(
    data: &[u8],
    out: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    let needed = data.len();

    if out.is_null() {
        if !out_written.is_null() {
            *out_written = needed;
        }
        return KMS_OK;
    }

    if out_len < needed {
        if !out_written.is_null() {
            *out_written = needed;
        }
        return KMS_ERR_BUFFER_TOO_SMALL;
    }

    std::ptr::copy_nonoverlapping(data.as_ptr(), out, needed);

    if !out_written.is_null() {
        *out_written = needed;
    }

    KMS_OK
}

// ---------------------------------------------------------------------------
// C-string readers
// ---------------------------------------------------------------------------

/// Read a C string into a `&str`, returning an error code on failure.
pub unsafe fn read_cstr<'a>(ptr: *const c_char) -> std::result::Result<&'a str, i32> {
    if ptr.is_null() {
        return Err(KMS_ERR_NULL_POINTER);
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| KMS_ERR_INVALID_INPUT)
}

/// Read an optional C string (NULL -> empty string).
pub unsafe fn read_cstr_optional<'a>(ptr: *const c_char) -> std::result::Result<&'a str, i32> {
    if ptr.is_null() {
        return Ok("");
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| KMS_ERR_INVALID_INPUT)
}
