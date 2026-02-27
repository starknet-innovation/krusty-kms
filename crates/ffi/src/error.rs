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
