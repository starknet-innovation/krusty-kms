//! Conversion helpers and output-buffer utilities.

use std::ffi::{c_char, CStr};

use serde::Serialize;
use serde_json::Value;
use starknet_types_core::curve::{AffinePoint, ProjectivePoint};
use starknet_types_core::felt::{Felt, NonZeroFelt};

use crate::error::*;
use crate::types::*;

/// Maximum number of felts accepted by `kms_poseidon_hash_many`.
pub const KMS_MAX_POSEIDON_VALUES: usize = 4096;

/// Maximum constructor calldata length for contract address derivation.
pub const KMS_MAX_CONSTRUCTOR_CALLDATA: usize = 1024;

/// Maximum BIP-39 entropy length in bytes (256-bit mnemonic).
pub const KMS_MAX_ENTROPY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Felt <-> KmsFelt
// ---------------------------------------------------------------------------

pub fn felt_to_kms(f: &Felt) -> KmsFelt {
    KmsFelt {
        bytes: f.to_bytes_be(),
    }
}

/// Decode a `KmsFelt` and reject non-canonical 32-byte encodings.
///
/// `Felt::from_bytes_be_slice` reduces values `>= p` to a different field
/// element. Language bindings that stuff raw 32-byte keys into `KmsFelt`
/// (JNI / Swift / Dart) would otherwise sign or prove with a key the caller
/// did not intend. The hex/bytes parsers already reject this (M-25); every
/// struct-passing entry point must use this checked decoder (H-3).
pub fn kms_to_felt(k: &KmsFelt) -> Result<Felt, i32> {
    let felt = Felt::from_bytes_be_slice(&k.bytes);
    if felt.to_bytes_be() != k.bytes {
        return Err(KMS_ERR_INVALID_INPUT);
    }
    Ok(felt)
}

/// Decode a slice of `KmsFelt` values, failing closed on the first
/// non-canonical encoding.
pub fn kms_slice_to_felts(values: &[KmsFelt]) -> Result<Vec<Felt>, i32> {
    values.iter().map(kms_to_felt).collect()
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

pub fn kms_to_proj(k: &KmsProjectivePoint) -> Result<ProjectivePoint, i32> {
    // Decode every coordinate first. A canonical `z == 0` identity must not
    // smuggle a non-canonical `x`/`y` past `KMS_ERR_INVALID_INPUT`.
    let x = kms_to_felt(&k.x)?;
    let y = kms_to_felt(&k.y)?;
    let z = kms_to_felt(&k.z)?;
    if z == Felt::ZERO {
        return Ok(ProjectivePoint::identity());
    }
    // Convert projective (X, Y, Z) → affine, avoiding ProjectivePoint::new
    // which changed signature in starknet-types-core 0.2.4.
    // Homogeneous projective: affine = (X/Z, Y/Z).
    let nz: NonZeroFelt = z.try_into().map_err(|_| KMS_ERR_INVALID_INPUT)?;
    let ax = x.field_div(&nz);
    let ay = y.field_div(&nz);
    ProjectivePoint::from_affine(ax, ay).map_err(|_| KMS_ERR_INVALID_INPUT)
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

    fn prime_bytes() -> [u8; 32] {
        let mut bytes = Felt::MAX.to_bytes_be();
        bytes[31] += 1;
        bytes
    }

    #[test]
    fn kms_to_felt_rejects_values_at_or_above_the_field_prime() {
        let canonical = felt_to_kms(&Felt::from(42u64));
        assert_eq!(kms_to_felt(&canonical).unwrap(), Felt::from(42u64));

        let max = felt_to_kms(&Felt::MAX);
        assert_eq!(kms_to_felt(&max).unwrap(), Felt::MAX);

        let prime = KmsFelt {
            bytes: prime_bytes(),
        };
        assert_eq!(kms_to_felt(&prime), Err(KMS_ERR_INVALID_INPUT));

        let all_ff = KmsFelt { bytes: [0xff; 32] };
        assert_eq!(kms_to_felt(&all_ff), Err(KMS_ERR_INVALID_INPUT));
    }

    #[test]
    fn kms_slice_to_felts_fails_closed_on_first_noncanonical() {
        let ok = felt_to_kms(&Felt::from(1u64));
        let bad = KmsFelt { bytes: [0xff; 32] };
        assert_eq!(kms_slice_to_felts(&[ok, bad]), Err(KMS_ERR_INVALID_INPUT));
        assert_eq!(kms_slice_to_felts(&[ok]).unwrap(), vec![Felt::from(1u64)]);
    }

    #[test]
    fn kms_to_proj_rejects_noncanonical_xy_when_z_is_zero() {
        let identity = proj_to_kms(&ProjectivePoint::identity());
        assert!(kms_to_proj(&identity).is_ok());

        let zero = felt_to_kms(&Felt::ZERO);
        let noncanonical = KmsFelt { bytes: [0xff; 32] };
        assert_eq!(
            kms_to_proj(&KmsProjectivePoint {
                x: noncanonical,
                y: zero,
                z: zero,
            }),
            Err(KMS_ERR_INVALID_INPUT)
        );
        assert_eq!(
            kms_to_proj(&KmsProjectivePoint {
                x: zero,
                y: noncanonical,
                z: zero,
            }),
            Err(KMS_ERR_INVALID_INPUT)
        );
    }
}
