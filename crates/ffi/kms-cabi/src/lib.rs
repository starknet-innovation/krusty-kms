//! C ABI shared library for GHOUL KMS.
//!
//! Produces `libkms.{so,dylib,dll}` implementing 26 C functions consumed by
//! language wrapper packages (Go, Python, Swift, Rust, JVM, C, TypeScript).
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

use std::ffi::{c_char, CStr};
use std::panic::catch_unwind;
use std::slice;

use starknet_types_core::curve::{AffinePoint, ProjectivePoint};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};

// ---------------------------------------------------------------------------
// Error codes (matching kms.h)
// ---------------------------------------------------------------------------

const KMS_OK: i32 = 0;
const KMS_ERR_NULL_POINTER: i32 = 1;
const KMS_ERR_INVALID_INPUT: i32 = 2;
const KMS_ERR_BUFFER_TOO_SMALL: i32 = 3;
const KMS_ERR_CRYPTO: i32 = 4;
const KMS_ERR_INTERNAL: i32 = 5;

// ---------------------------------------------------------------------------
// ABI version
// ---------------------------------------------------------------------------

const ABI_MAJOR: u32 = 1;
const ABI_MINOR: u32 = 0;

// ---------------------------------------------------------------------------
// #[repr(C)] types matching kms.h
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsFelt {
    pub bytes: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsProjectivePoint {
    pub x: KmsFelt,
    pub y: KmsFelt,
    pub z: KmsFelt,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsAffinePoint {
    pub x: KmsFelt,
    pub y: KmsFelt,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsTongoKeyPair {
    pub private_key: KmsFelt,
    pub public_key: KmsProjectivePoint,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsNostrKeyPair {
    pub private_key: [u8; 32],
    pub public_key_xonly: [u8; 32],
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn felt_to_kms(f: &Felt) -> KmsFelt {
    KmsFelt {
        bytes: f.to_bytes_be(),
    }
}

fn kms_to_felt(k: &KmsFelt) -> Felt {
    Felt::from_bytes_be_slice(&k.bytes)
}

fn proj_to_kms(p: &ProjectivePoint) -> KmsProjectivePoint {
    // Access the internal coordinates via affine conversion or direct field access.
    // ProjectivePoint stores (x, y, z). We serialize each coordinate to bytes.
    // Since ProjectivePoint doesn't expose x/y/z directly, we use a workaround:
    // serialize the point data using the internal representation.
    //
    // starknet_types_core::curve::ProjectivePoint has x(), y(), z() methods
    // that return Felt references (added in 0.2.x).
    KmsProjectivePoint {
        x: felt_to_kms(&p.x()),
        y: felt_to_kms(&p.y()),
        z: felt_to_kms(&p.z()),
    }
}

fn kms_to_proj(k: &KmsProjectivePoint) -> ProjectivePoint {
    let x = kms_to_felt(&k.x);
    let y = kms_to_felt(&k.y);
    let z = kms_to_felt(&k.z);
    ProjectivePoint::new_unchecked(x, y, z)
}

fn affine_to_kms(a: &AffinePoint) -> KmsAffinePoint {
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
/// - If `out` is NULL: write the needed byte count (excluding NUL) to `*out_written`, return OK.
/// - If `out` is non-NULL and `out_len` is sufficient: write string + NUL, set `*out_written`.
/// - Otherwise: return `KMS_ERR_BUFFER_TOO_SMALL`.
unsafe fn write_string_output(
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
unsafe fn write_bytes_output(
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

/// Read a C string into a `&str`, returning an error code on failure.
unsafe fn read_cstr<'a>(ptr: *const c_char) -> std::result::Result<&'a str, i32> {
    if ptr.is_null() {
        return Err(KMS_ERR_NULL_POINTER);
    }
    CStr::from_ptr(ptr).to_str().map_err(|_| KMS_ERR_INVALID_INPUT)
}

/// Read an optional C string (NULL → empty string).
unsafe fn read_cstr_optional<'a>(ptr: *const c_char) -> std::result::Result<&'a str, i32> {
    if ptr.is_null() {
        return Ok("");
    }
    CStr::from_ptr(ptr).to_str().map_err(|_| KMS_ERR_INVALID_INPUT)
}

// ---------------------------------------------------------------------------
// Version / ABI (2 functions)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_get_abi_version(major: *mut u32, minor: *mut u32) -> i32 {
    catch_unwind(|| {
        if major.is_null() || minor.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        *major = ABI_MAJOR;
        *minor = ABI_MINOR;
        KMS_OK
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_get_version_string(
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        let version = env!("CARGO_PKG_VERSION");
        write_string_output(version, out, out_len, out_written)
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Felt ops (4 functions)
// ---------------------------------------------------------------------------

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

        // Validate hex string
        let trimmed = s.strip_prefix("0x").unwrap_or(s);
        if trimmed.is_empty() || trimmed.len() > 64 {
            return KMS_ERR_INVALID_INPUT;
        }
        if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return KMS_ERR_INVALID_INPUT;
        }

        let felt = Felt::from_hex_unchecked(s);
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
        let felt = kms_to_felt(&*value);
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
        let felt = kms_to_felt(&*value);
        let bytes = felt.to_bytes_be();
        write_bytes_output(&bytes, out, out_len, out_written)
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Point ops (2 functions)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_projective_from_affine(
    affine: *const KmsAffinePoint,
    out: *mut KmsProjectivePoint,
) -> i32 {
    catch_unwind(|| {
        if affine.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        let x = kms_to_felt(&(*affine).x);
        let y = kms_to_felt(&(*affine).y);

        let ap = match AffinePoint::new(x, y) {
            Ok(ap) => ap,
            Err(_) => return KMS_ERR_INVALID_INPUT,
        };
        let proj = she_core::StarkCurve::affine_to_projective(&ap);
        *out = proj_to_kms(&proj);
        KMS_OK
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_projective_to_affine(
    point: *const KmsProjectivePoint,
    out: *mut KmsAffinePoint,
) -> i32 {
    catch_unwind(|| {
        if point.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        let proj = kms_to_proj(&*point);
        match she_core::StarkCurve::projective_to_affine(&proj) {
            Ok(ap) => {
                *out = affine_to_kms(&ap);
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Hash (2 functions)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_pedersen_hash(
    left: *const KmsFelt,
    right: *const KmsFelt,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        if left.is_null() || right.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        let l = kms_to_felt(&*left);
        let r = kms_to_felt(&*right);
        let h = Pedersen::hash(&l, &r);
        *out = felt_to_kms(&h);
        KMS_OK
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_poseidon_hash_many(
    values: *const KmsFelt,
    values_len: usize,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        if out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        if values_len > 0 && values.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let felts: Vec<Felt> = if values_len == 0 {
            vec![]
        } else {
            let kms_felts = slice::from_raw_parts(values, values_len);
            kms_felts.iter().map(kms_to_felt).collect()
        };

        let h = she_core::poseidon_hash_many(&felts);
        *out = felt_to_kms(&h);
        KMS_OK
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Mnemonic (4 functions)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_generate_mnemonic(
    word_count: u32,
    out: *mut c_char,
    out_len: usize,
    out_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        match kms::generate_mnemonic(word_count as usize) {
            Ok(m) => write_string_output(&m, out, out_len, out_written),
            Err(_) => KMS_ERR_INVALID_INPUT,
        }
    })
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
        match kms::validate_mnemonic(s) {
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

        match kms::mnemonic_to_seed(mnemonic_str, pass_str) {
            Ok(seed) => write_bytes_output(&seed, out, out_len, out_written),
            Err(_) => KMS_ERR_INVALID_INPUT,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Key derivation (6 functions)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_derive_private_key_with_coin_type(
    mnemonic: *const c_char,
    index: u32,
    account_index: u32,
    coin_type: u32,
    passphrase: *const c_char,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        let m = match read_cstr(mnemonic) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let p = match read_cstr_optional(passphrase) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let pass = if p.is_empty() { None } else { Some(p) };
        match kms::derive_private_key_with_coin_type(m, index, account_index, coin_type, pass) {
            Ok(key) => {
                *out = felt_to_kms(&key);
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_derive_keypair_with_coin_type(
    mnemonic: *const c_char,
    index: u32,
    account_index: u32,
    coin_type: u32,
    passphrase: *const c_char,
    out: *mut KmsTongoKeyPair,
) -> i32 {
    catch_unwind(|| {
        let m = match read_cstr(mnemonic) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let p = match read_cstr_optional(passphrase) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let pass = if p.is_empty() { None } else { Some(p) };
        match kms::derive_keypair_with_coin_type(m, index, account_index, coin_type, pass) {
            Ok(kp) => {
                *out = KmsTongoKeyPair {
                    private_key: felt_to_kms(&kp.private_key),
                    public_key: proj_to_kms(&kp.public_key),
                };
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_derive_view_private_key(
    mnemonic: *const c_char,
    index: u32,
    account_index: u32,
    passphrase: *const c_char,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        let m = match read_cstr(mnemonic) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let p = match read_cstr_optional(passphrase) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let pass = if p.is_empty() { None } else { Some(p) };
        match kms::derive_view_private_key(m, index, account_index, pass) {
            Ok(key) => {
                *out = felt_to_kms(&key);
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_derive_view_keypair(
    mnemonic: *const c_char,
    index: u32,
    account_index: u32,
    passphrase: *const c_char,
    out: *mut KmsTongoKeyPair,
) -> i32 {
    catch_unwind(|| {
        let m = match read_cstr(mnemonic) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let p = match read_cstr_optional(passphrase) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let pass = if p.is_empty() { None } else { Some(p) };
        match kms::derive_view_keypair(m, index, account_index, pass) {
            Ok(kp) => {
                *out = KmsTongoKeyPair {
                    private_key: felt_to_kms(&kp.private_key),
                    public_key: proj_to_kms(&kp.public_key),
                };
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_derive_nostr_private_key(
    mnemonic: *const c_char,
    index: u32,
    account_index: u32,
    passphrase: *const c_char,
    out: *mut u8,
) -> i32 {
    catch_unwind(|| {
        let m = match read_cstr(mnemonic) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let p = match read_cstr_optional(passphrase) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let pass = if p.is_empty() { None } else { Some(p) };
        match kms::derive_nostr_private_key(m, index, account_index, pass) {
            Ok(key) => {
                std::ptr::copy_nonoverlapping(key.as_ptr(), out, 32);
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_derive_nostr_keypair(
    mnemonic: *const c_char,
    index: u32,
    account_index: u32,
    passphrase: *const c_char,
    out: *mut KmsNostrKeyPair,
) -> i32 {
    catch_unwind(|| {
        let m = match read_cstr(mnemonic) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let p = match read_cstr_optional(passphrase) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let pass = if p.is_empty() { None } else { Some(p) };
        match kms::derive_nostr_keypair(m, index, account_index, pass) {
            Ok(kp) => {
                *out = KmsNostrKeyPair {
                    private_key: kp.private_key,
                    public_key_xonly: kp.public_key,
                };
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Address (2 functions)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kms_calculate_contract_address(
    salt: *const KmsFelt,
    class_hash: *const KmsFelt,
    constructor_calldata: *const KmsFelt,
    constructor_calldata_len: usize,
    deployer_address: *const KmsFelt,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        if salt.is_null() || class_hash.is_null() || deployer_address.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }
        if constructor_calldata_len > 0 && constructor_calldata.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let s = kms_to_felt(&*salt);
        let ch = kms_to_felt(&*class_hash);
        let da = kms_to_felt(&*deployer_address);

        let calldata: Vec<Felt> = if constructor_calldata_len == 0 {
            vec![]
        } else {
            let kms_cd = slice::from_raw_parts(constructor_calldata, constructor_calldata_len);
            kms_cd.iter().map(kms_to_felt).collect()
        };

        match kms::calculate_contract_address(&s, &ch, &calldata, &da) {
            Ok(addr) => {
                *out = felt_to_kms(&addr);
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn kms_derive_oz_account_address(
    public_key_x: *const KmsFelt,
    class_hash: *const KmsFelt,
    salt: *const KmsFelt,
    out: *mut KmsFelt,
) -> i32 {
    catch_unwind(|| {
        if public_key_x.is_null() || class_hash.is_null() || out.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let pk = kms_to_felt(&*public_key_x);
        let ch = kms_to_felt(&*class_hash);
        let s = if salt.is_null() {
            None
        } else {
            Some(kms_to_felt(&*salt))
        };

        match kms::derive_oz_account_address(&pk, &ch, s.as_ref()) {
            Ok(addr) => {
                *out = felt_to_kms(&addr);
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Coin types (4 functions)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn kms_get_coin_type_tongo() -> u32 {
    kms::TONGO_COIN_TYPE
}

#[no_mangle]
pub extern "C" fn kms_get_coin_type_starknet() -> u32 {
    kms::STARKNET_COIN_TYPE
}

#[no_mangle]
pub extern "C" fn kms_get_coin_type_tongo_view() -> u32 {
    kms::TONGO_VIEW_COIN_TYPE
}

#[no_mangle]
pub extern "C" fn kms_get_coin_type_nostr() -> u32 {
    kms::NOSTR_COIN_TYPE
}

// ---------------------------------------------------------------------------
// Error (2 functions)
// ---------------------------------------------------------------------------

static ERROR_NAMES: &[&[u8]] = &[
    b"KMS_OK\0",
    b"KMS_ERR_NULL_POINTER\0",
    b"KMS_ERR_INVALID_INPUT\0",
    b"KMS_ERR_BUFFER_TOO_SMALL\0",
    b"KMS_ERR_CRYPTO\0",
    b"KMS_ERR_INTERNAL\0",
];

static ERROR_MESSAGES: &[&[u8]] = &[
    b"success\0",
    b"null pointer argument\0",
    b"invalid input\0",
    b"buffer too small\0",
    b"cryptographic operation failed\0",
    b"internal error (panic)\0",
];

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_felt_conversion_roundtrip() {
        let felt = Felt::from(42u64);
        let kms = felt_to_kms(&felt);
        let back = kms_to_felt(&kms);
        assert_eq!(felt, back);
    }

    #[test]
    fn test_projective_conversion_roundtrip() {
        let point = she_core::StarkCurve::GENERATOR;
        let kms = proj_to_kms(&point);
        let back = kms_to_proj(&kms);

        let a1 = she_core::StarkCurve::projective_to_affine(&point).unwrap();
        let a2 = she_core::StarkCurve::projective_to_affine(&back).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_error_name_valid() {
        unsafe {
            let name = kms_error_name(0);
            assert!(!name.is_null());
            let s = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(s, "KMS_OK");
        }
    }

    #[test]
    fn test_error_name_invalid() {
        unsafe {
            let name = kms_error_name(999);
            assert!(!name.is_null());
            let s = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(s, "KMS_ERR_INTERNAL");
        }
    }

    #[test]
    fn test_error_message_valid() {
        unsafe {
            let msg = kms_error_message(1);
            assert!(!msg.is_null());
            let s = CStr::from_ptr(msg).to_str().unwrap();
            assert_eq!(s, "null pointer argument");
        }
    }

    #[test]
    fn test_coin_types() {
        assert_eq!(kms_get_coin_type_tongo(), 5454);
        assert_eq!(kms_get_coin_type_starknet(), 9004);
        assert_eq!(kms_get_coin_type_tongo_view(), 5353);
        assert_eq!(kms_get_coin_type_nostr(), 1237);
    }

    #[test]
    fn test_abi_version() {
        let mut major = 0u32;
        let mut minor = 0u32;
        let rc = unsafe { kms_get_abi_version(&mut major, &mut minor) };
        assert_eq!(rc, KMS_OK);
        assert_eq!(major, 1);
        assert_eq!(minor, 0);
    }

    #[test]
    fn test_version_string() {
        let mut written = 0usize;
        // First call: get size
        let rc = unsafe {
            kms_get_version_string(std::ptr::null_mut(), 0, &mut written)
        };
        assert_eq!(rc, KMS_OK);
        assert!(written > 0);

        // Second call: get string
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
        let rc = unsafe { kms_felt_from_hex(hex.as_ptr(), &mut felt) };
        assert_eq!(rc, KMS_OK);

        // Convert back to hex
        let mut written = 0usize;
        let rc = unsafe {
            kms_felt_to_hex(&felt, std::ptr::null_mut(), 0, &mut written)
        };
        assert_eq!(rc, KMS_OK);

        let mut buf = vec![0u8; written + 1];
        let rc = unsafe {
            kms_felt_to_hex(&felt, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut written)
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
        let rc = unsafe { kms_felt_from_bytes_be(input.as_ptr(), input.len(), &mut felt) };
        assert_eq!(rc, KMS_OK);

        let mut out = [0u8; 32];
        let mut written = 0usize;
        let rc = unsafe {
            kms_felt_to_bytes_be(&felt, out.as_mut_ptr(), out.len(), &mut written)
        };
        assert_eq!(rc, KMS_OK);
        assert_eq!(written, 32);
        assert_eq!(out[31], 42);
    }

    #[test]
    fn test_pedersen_hash() {
        let a = felt_to_kms(&Felt::from(1u64));
        let b = felt_to_kms(&Felt::from(2u64));
        let mut out = KmsFelt { bytes: [0; 32] };
        let rc = unsafe { kms_pedersen_hash(&a, &b, &mut out) };
        assert_eq!(rc, KMS_OK);
        assert_ne!(out.bytes, [0; 32]);
    }

    #[test]
    fn test_null_pointer_errors() {
        let rc = unsafe { kms_get_abi_version(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(rc, KMS_ERR_NULL_POINTER);

        let rc = unsafe { kms_felt_from_hex(std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(rc, KMS_ERR_NULL_POINTER);
    }
}
