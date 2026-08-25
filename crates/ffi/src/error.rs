//! Error codes and human-readable error helpers.

use std::ffi::c_char;

// ---------------------------------------------------------------------------
// Error codes (matching kms.h)
// ---------------------------------------------------------------------------

pub const KMS_OK: i32 = 0;
pub const KMS_ERR_NULL_POINTER: i32 = 1;
pub const KMS_ERR_INVALID_INPUT: i32 = 2;
pub const KMS_ERR_BUFFER_TOO_SMALL: i32 = 3;
pub const KMS_ERR_CRYPTO: i32 = 4;
pub const KMS_ERR_INTERNAL: i32 = 5;
pub const KMS_ERR_INVALID_HANDLE: i32 = 6;
pub const KMS_ERR_JSON: i32 = 7;

// ---------------------------------------------------------------------------
// Decode failures
// ---------------------------------------------------------------------------

/// A struct-passing FFI input that failed to decode.
///
/// The `KmsFelt` / `KmsProjectivePoint` decoders in [`crate::helpers`] report
/// failure with this rather than a bare status code, so a rejected input and a
/// decoded value never share one all-numeric `Result`. The error arm carries no
/// number at all; the C status code is produced only at the boundary, by
/// [`InvalidInput::to_status`].
///
/// This is a type-safety change, and on its own it is *not* what closed CodeQL
/// alert #56. That alert is about the shape of the bail, not the error type: an
/// early `return <status>` inside a `match` arm is modelled as a value of that
/// `match`, so the binding inherited the error constant and read as a
/// hard-coded salt reaching `calculate_contract_address`. Decoder call sites
/// bail with `let ... else` for that reason -- see
/// `docs/design/2026-08-24-typed-ffi-decode-failure.md` before turning one back
/// into a `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidInput;

impl InvalidInput {
    /// The status code a C caller sees for a rejected input.
    ///
    /// Deliberately an inherent method rather than `From<InvalidInput> for
    /// i32`: `From` would let `?` widen a decode failure into any helper
    /// returning `Result<_, i32>`, putting a status code back beside a decoded
    /// value one layer up. Widening happens explicitly, at an `extern "C"`
    /// boundary, or it does not compile.
    pub const fn to_status(self) -> i32 {
        KMS_ERR_INVALID_INPUT
    }
}

// ---------------------------------------------------------------------------
// Error tables
// ---------------------------------------------------------------------------

static ERROR_NAMES: &[&[u8]] = &[
    b"KMS_OK\0",
    b"KMS_ERR_NULL_POINTER\0",
    b"KMS_ERR_INVALID_INPUT\0",
    b"KMS_ERR_BUFFER_TOO_SMALL\0",
    b"KMS_ERR_CRYPTO\0",
    b"KMS_ERR_INTERNAL\0",
    b"KMS_ERR_INVALID_HANDLE\0",
    b"KMS_ERR_JSON\0",
];

static ERROR_MESSAGES: &[&[u8]] = &[
    b"success\0",
    b"null pointer argument\0",
    b"invalid input\0",
    b"buffer too small\0",
    b"cryptographic operation failed\0",
    b"internal error (panic)\0",
    b"invalid account handle\0",
    b"JSON serialization/deserialization failed\0",
];

// ---------------------------------------------------------------------------
// FFI functions
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn kms_error_name(code: i32) -> *const c_char {
    if code >= 0 && (code as usize) < ERROR_NAMES.len() {
        ERROR_NAMES[code as usize].as_ptr() as *const c_char
    } else {
        ERROR_NAMES[KMS_ERR_INTERNAL as usize].as_ptr() as *const c_char
    }
}

#[no_mangle]
pub extern "C" fn kms_error_message(code: i32) -> *const c_char {
    if code >= 0 && (code as usize) < ERROR_MESSAGES.len() {
        ERROR_MESSAGES[code as usize].as_ptr() as *const c_char
    } else {
        ERROR_MESSAGES[KMS_ERR_INTERNAL as usize].as_ptr() as *const c_char
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_input_maps_to_the_invalid_input_status() {
        // Every decoder call site bails with `InvalidInput.to_status()`, so
        // this method is the one place the numeric contract with C callers is
        // decided.
        assert_eq!(InvalidInput.to_status(), KMS_ERR_INVALID_INPUT);
    }
}
