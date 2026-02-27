//! Account management FFI functions.

use std::ffi::c_char;
use std::panic::catch_unwind;

use krusty_kms_common::AccountState;
use krusty_kms_sdk::TongoAccount;

use crate::error::*;
use crate::handle;
use crate::helpers::*;
use crate::types::*;

// ---------------------------------------------------------------------------
// Helpers for u128 <-> (u64_low, u64_high)
// ---------------------------------------------------------------------------

fn u128_to_pair(v: u128) -> (u64, u64) {
    (v as u64, (v >> 64) as u64)
}

fn pair_to_u128(low: u64, high: u64) -> u128 {
    (high as u128) << 64 | (low as u128)
}

// ---------------------------------------------------------------------------
// FFI functions
// ---------------------------------------------------------------------------

/// Create a `TongoAccount` from a mnemonic and return an opaque handle.
#[no_mangle]
pub unsafe extern "C" fn kms_account_create_from_mnemonic(
    mnemonic: *const c_char,
    index: u32,
    account_index: u32,
    contract_address: *const KmsFelt,
    passphrase: *const c_char,
    out_handle: *mut KmsAccountHandle,
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
        if contract_address.is_null() || out_handle.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let addr = kms_to_felt(&*contract_address);
        let pass = if p.is_empty() { None } else { Some(p) };

        let account = match TongoAccount::from_mnemonic(m, index, account_index, addr, pass) {
            Ok(a) => a,
            Err(_) => return KMS_ERR_CRYPTO,
        };

        match handle::insert(account) {
            Ok(h) => {
                *out_handle = h;
                KMS_OK
            }
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

/// Create a `TongoAccount` from explicit owner + view private keys.
#[no_mangle]
pub unsafe extern "C" fn kms_account_create_from_keys(
    owner_key: *const KmsFelt,
    view_key: *const KmsFelt,
    contract_address: *const KmsFelt,
    out_handle: *mut KmsAccountHandle,
) -> i32 {
    catch_unwind(|| {
        if owner_key.is_null()
            || view_key.is_null()
            || contract_address.is_null()
            || out_handle.is_null()
        {
            return KMS_ERR_NULL_POINTER;
        }

        let ok = kms_to_felt(&*owner_key);
        let vk = kms_to_felt(&*view_key);
        let addr = kms_to_felt(&*contract_address);

        let account = match TongoAccount::from_keys(ok, vk, addr) {
            Ok(a) => a,
            Err(_) => return KMS_ERR_CRYPTO,
        };

        match handle::insert(account) {
            Ok(h) => {
                *out_handle = h;
                KMS_OK
            }
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

/// Read the current state of an account.
#[no_mangle]
pub unsafe extern "C" fn kms_account_get_state(
    h: KmsAccountHandle,
    out_state: *mut KmsAccountState,
) -> i32 {
    catch_unwind(|| {
        if out_state.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        match handle::with(h, |acc| {
            let (bl, bh) = u128_to_pair(acc.state.balance);
            let (pl, ph) = u128_to_pair(acc.state.pending_balance);
            *out_state = KmsAccountState {
                balance_low: bl,
                balance_high: bh,
                pending_balance_low: pl,
                pending_balance_high: ph,
                nonce: acc.state.nonce,
            };
            Ok(KMS_OK)
        }) {
            Ok(code) => code,
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

/// Update the state of an account.
#[no_mangle]
pub unsafe extern "C" fn kms_account_update_state(
    h: KmsAccountHandle,
    state: *const KmsAccountState,
) -> i32 {
    catch_unwind(|| {
        if state.is_null() {
            return KMS_ERR_NULL_POINTER;
        }

        let s = &*state;
        let new_state = AccountState {
            balance: pair_to_u128(s.balance_low, s.balance_high),
            pending_balance: pair_to_u128(s.pending_balance_low, s.pending_balance_high),
            nonce: s.nonce,
        };

        match handle::with_mut(h, |acc| {
            acc.update_state(new_state);
            Ok(KMS_OK)
        }) {
            Ok(code) => code,
            Err(e) => e,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

/// Destroy an account, releasing its resources.
#[no_mangle]
pub unsafe extern "C" fn kms_account_destroy(h: KmsAccountHandle) -> i32 {
    catch_unwind(|| match handle::remove(h) {
        Ok(()) => KMS_OK,
        Err(e) => e,
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_types_core::felt::Felt;
    use std::ffi::CString;

    const TEST_MNEMONIC: &str =
        "habit hope tip crystal because grunt nation idea electric witness alert like";

    #[test]
    fn test_account_lifecycle() {
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let contract_addr = felt_to_kms(&Felt::from(123456u64));
        let mut h: KmsAccountHandle = 0;

        // Create
        let rc = unsafe {
            kms_account_create_from_mnemonic(
                mnemonic.as_ptr(),
                0,
                0,
                &contract_addr,
                std::ptr::null(),
                &mut h,
            )
        };
        assert_eq!(rc, KMS_OK);
        assert_ne!(h, 0);

        // Get state (default zeros)
        let mut state = KmsAccountState {
            balance_low: 0,
            balance_high: 0,
            pending_balance_low: 0,
            pending_balance_high: 0,
            nonce: 0,
        };
        let rc = unsafe { kms_account_get_state(h, &mut state) };
        assert_eq!(rc, KMS_OK);
        assert_eq!(state.balance_low, 0);

        // Update state
        state.balance_low = 1000;
        state.nonce = 5;
        let rc = unsafe { kms_account_update_state(h, &state) };
        assert_eq!(rc, KMS_OK);

        // Verify
        let mut state2 = KmsAccountState {
            balance_low: 0,
            balance_high: 0,
            pending_balance_low: 0,
            pending_balance_high: 0,
            nonce: 0,
        };
        let rc = unsafe { kms_account_get_state(h, &mut state2) };
        assert_eq!(rc, KMS_OK);
        assert_eq!(state2.balance_low, 1000);
        assert_eq!(state2.nonce, 5);

        // Destroy
        let rc = unsafe { kms_account_destroy(h) };
        assert_eq!(rc, KMS_OK);

        // Double destroy should fail
        let rc = unsafe { kms_account_destroy(h) };
        assert_eq!(rc, KMS_ERR_INVALID_HANDLE);
    }

    #[test]
    fn test_account_from_keys() {
        let owner = felt_to_kms(&Felt::from(42u64));
        let view = felt_to_kms(&Felt::from(123u64));
        let addr = felt_to_kms(&Felt::from(456u64));
        let mut h: KmsAccountHandle = 0;

        let rc = unsafe { kms_account_create_from_keys(&owner, &view, &addr, &mut h) };
        assert_eq!(rc, KMS_OK);
        assert_ne!(h, 0);

        let rc = unsafe { kms_account_destroy(h) };
        assert_eq!(rc, KMS_OK);
    }
}
