//! Key derivation FFI functions.

use std::ffi::c_char;
use std::panic::catch_unwind;

use crate::error::*;
use crate::helpers::*;
use crate::types::*;

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
        match krusty_kms::derive_private_key_with_coin_type(
            m,
            index,
            account_index,
            coin_type,
            pass,
        ) {
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
        match krusty_kms::derive_keypair_with_coin_type(m, index, account_index, coin_type, pass) {
            Ok(kp) => {
                *out = KmsTongoKeyPair {
                    private_key: felt_to_kms(kp.private_key.expose_secret()),
                    public_key: proj_to_kms(&kp.public_key),
                };
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

/// Derive a Nostr (secp256k1) private key from a BIP-39 mnemonic.
///
/// # Buffer contract
///
/// `out` **must** point to a caller-owned buffer of **exactly 32 bytes**.
/// This ABI does not take an `out_len` parameter; wrappers must allocate 32
/// bytes (see `uint8_t out[32]` in `kms.h`). Exactly 32 bytes are always
/// written on success.
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
        match krusty_kms::derive_nostr_private_key(m, index, account_index, pass) {
            Ok(key) => {
                debug_assert_eq!(key.len(), 32, "Nostr private key must be 32 bytes");
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
        match krusty_kms::derive_nostr_keypair(m, index, account_index, pass) {
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
