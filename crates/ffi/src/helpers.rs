//! Conversion helpers and output-buffer utilities.

use std::ffi::{c_char, CStr};

use serde::Serialize;
use serde_json::Value;
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

/// Deterministic fixed-width hex encoding for Stark felts.
///
/// Format: `0x` + 64 lowercase hex digits.
pub fn felt_hex_fixed(f: &Felt) -> String {
    format!("0x{:064x}", f)
}

fn normalize_hex_string(s: &str) -> Option<String> {
    if !(s.starts_with("0x") || s.starts_with("0X")) || s.len() <= 2 {
        return None;
    }
    if !s[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let felt = Felt::from_hex(s).ok()?;
    Some(felt_hex_fixed(&felt))
}

fn normalize_hex_json(value: &mut Value) {
    match value {
        Value::String(s) => {
            if let Some(normalized) = normalize_hex_string(s) {
                *s = normalized;
            }
        }
        Value::Array(items) => {
            for item in items {
                normalize_hex_json(item);
            }
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                normalize_hex_json(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Serialize any serde value to JSON while normalizing hex-string fields to a
/// deterministic fixed-width felt format.
pub fn to_deterministic_json<T: Serialize>(value: &T) -> Result<String, i32> {
    let mut json_value = serde_json::to_value(value).map_err(|_| KMS_ERR_JSON)?;
    normalize_hex_json(&mut json_value);
    serde_json::to_string(&json_value).map_err(|_| KMS_ERR_JSON)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct HexProbe<'a> {
        value: &'a str,
    }

    #[test]
    fn deterministic_hex_json_has_stable_width() {
        let short = to_deterministic_json(&HexProbe { value: "0x1" }).unwrap();
        let long = to_deterministic_json(&HexProbe { value: "0xabcdef" }).unwrap();

        assert_eq!(short.len(), long.len());
        assert!(
            short.contains("0x0000000000000000000000000000000000000000000000000000000000000001")
        );
        assert!(long.contains("0x0000000000000000000000000000000000000000000000000000000000abcdef"));
    }
}
