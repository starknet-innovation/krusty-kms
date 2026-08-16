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
        // Reject non-canonical values (>= field prime) instead of silently
        // reducing mod p: a 32-byte key >= p would otherwise alias to a
        // *different* key here while the JSON paths reject it (M-25).
        let canonical = format!("{felt:064x}");
        let padded_input = format!("{:0>64}", trimmed.to_ascii_lowercase());
        if canonical != padded_input {
            return KMS_ERR_INVALID_INPUT;
        }
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
        let felt = match kms_to_felt(&*value) {
            Ok(felt) => felt,
            Err(code) => return code,
        };
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
        // Reject non-canonical values (>= field prime) instead of silently
        // reducing mod p (M-25): if the round-trip does not reproduce the
        // input, the input aliased to a different field element. Only full
        // 32-byte inputs can reach the prime.
        let round_trip = felt.to_bytes_be();
        let (leading, tail) = round_trip.split_at(32 - bytes_len);
        if tail != data || leading.iter().any(|byte| *byte != 0) {
            return KMS_ERR_INVALID_INPUT;
        }
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
        let felt = match kms_to_felt(&*value) {
            Ok(felt) => felt,
            Err(code) => return code,
        };
        let bytes = felt.to_bytes_be();
        write_bytes_output(&bytes, out, out_len, out_written)
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stark field prime as 64 hex chars (no prefix).
    const PRIME_HEX: &str = "0800000000000011000000000000000000000000000000000000000000000001";

    fn prime_bytes() -> [u8; 32] {
        let mut bytes = Felt::MAX.to_bytes_be();
        // Felt::MAX = p - 1, which ends in 0x00; incrementing yields p exactly.
        bytes[31] += 1;
        bytes
    }

    /// Values >= p must be rejected, not silently reduced to a different
    /// field element (M-25).
    #[test]
    fn from_hex_rejects_noncanonical_values() {
        let mut out = KmsFelt { bytes: [0; 32] };

        let prime = std::ffi::CString::new(format!("0x{PRIME_HEX}")).unwrap();
        assert_eq!(
            unsafe { kms_felt_from_hex(prime.as_ptr(), &mut out) },
            KMS_ERR_INVALID_INPUT
        );

        let all_f = std::ffi::CString::new(format!("0x{}", "f".repeat(64))).unwrap();
        assert_eq!(
            unsafe { kms_felt_from_hex(all_f.as_ptr(), &mut out) },
            KMS_ERR_INVALID_INPUT
        );

        // p - 1 (Felt::MAX) is canonical and must round-trip, prefix or not,
        // in either case.
        let max_hex = format!("{:064x}", Felt::MAX);
        for input in [format!("0x{max_hex}"), max_hex.to_ascii_uppercase()] {
            let cstr = std::ffi::CString::new(input).unwrap();
            assert_eq!(
                unsafe { kms_felt_from_hex(cstr.as_ptr(), &mut out) },
                KMS_OK
            );
            assert_eq!(kms_to_felt(&out).unwrap(), Felt::MAX);
        }

        // Short canonical values (with leading zeros implied) still parse.
        let short = std::ffi::CString::new("0x2a").unwrap();
        assert_eq!(
            unsafe { kms_felt_from_hex(short.as_ptr(), &mut out) },
            KMS_OK
        );
        assert_eq!(kms_to_felt(&out).unwrap(), Felt::from(42u64));
    }

    /// 32-byte inputs >= p must be rejected, not silently reduced (M-25).
    #[test]
    fn from_bytes_be_rejects_noncanonical_values() {
        let mut out = KmsFelt { bytes: [0; 32] };

        let prime = prime_bytes();
        assert_eq!(
            unsafe { kms_felt_from_bytes_be(prime.as_ptr(), prime.len(), &mut out) },
            KMS_ERR_INVALID_INPUT
        );

        let max = Felt::MAX.to_bytes_be();
        assert_eq!(
            unsafe { kms_felt_from_bytes_be(max.as_ptr(), max.len(), &mut out) },
            KMS_OK
        );
        assert_eq!(kms_to_felt(&out).unwrap(), Felt::MAX);

        // Short inputs and 32-byte inputs with leading zeros stay accepted.
        let small = [0u8, 0, 0, 42];
        assert_eq!(
            unsafe { kms_felt_from_bytes_be(small.as_ptr(), small.len(), &mut out) },
            KMS_OK
        );
        assert_eq!(kms_to_felt(&out).unwrap(), Felt::from(42u64));
    }

    #[test]
    fn to_hex_and_bytes_reject_noncanonical_struct_values() {
        let prime = KmsFelt {
            bytes: prime_bytes(),
        };
        let mut written = 0usize;
        assert_eq!(
            unsafe { kms_felt_to_hex(&prime, std::ptr::null_mut(), 0, &mut written) },
            KMS_ERR_INVALID_INPUT
        );
        let mut out = [0u8; 32];
        assert_eq!(
            unsafe { kms_felt_to_bytes_be(&prime, out.as_mut_ptr(), out.len(), &mut written) },
            KMS_ERR_INVALID_INPUT
        );
    }
}
