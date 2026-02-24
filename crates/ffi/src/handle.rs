//! Thread-safe opaque handle registry for `TongoAccount`.
//!
//! Every `TongoAccount` created through the FFI is stored here behind a
//! monotonic `u64` handle.  Callers interact with accounts exclusively via
//! their handle, which avoids passing Rust objects across the C ABI.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use krusty_kms_sdk::TongoAccount;

use crate::error::*;

/// Global account registry.
static REGISTRY: Mutex<Option<HashMap<u64, Box<TongoAccount>>>> = Mutex::new(None);

/// Monotonic handle counter (0 is reserved as "invalid").
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn with_registry<F, R>(f: F) -> Result<R, i32>
where
    F: FnOnce(&mut HashMap<u64, Box<TongoAccount>>) -> Result<R, i32>,
{
    let mut guard = REGISTRY.lock().map_err(|_| KMS_ERR_INTERNAL)?;
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// Insert a new account and return its handle.
pub fn insert(account: TongoAccount) -> Result<u64, i32> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    with_registry(|map| {
        map.insert(id, Box::new(account));
        Ok(id)
    })
}

/// Run a closure with an immutable reference to the account behind `handle`.
pub fn with<F, R>(handle: u64, f: F) -> Result<R, i32>
where
    F: FnOnce(&TongoAccount) -> Result<R, i32>,
{
    with_registry(|map| {
        let account = map.get(&handle).ok_or(KMS_ERR_INVALID_HANDLE)?;
        f(account)
    })
}

/// Run a closure with a mutable reference to the account behind `handle`.
pub fn with_mut<F, R>(handle: u64, f: F) -> Result<R, i32>
where
    F: FnOnce(&mut TongoAccount) -> Result<R, i32>,
{
    with_registry(|map| {
        let account = map.get_mut(&handle).ok_or(KMS_ERR_INVALID_HANDLE)?;
        f(account)
    })
}

/// Remove an account from the registry and drop it.
pub fn remove(handle: u64) -> Result<(), i32> {
    with_registry(|map| {
        map.remove(&handle).ok_or(KMS_ERR_INVALID_HANDLE)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_types_core::felt::Felt;

    fn test_account() -> TongoAccount {
        TongoAccount::from_private_key(Felt::from(42u64), Felt::from(123u64)).unwrap()
    }

    #[test]
    fn insert_and_with() {
        let h = insert(test_account()).unwrap();
        let bal = with(h, |acc| Ok(acc.state.balance)).unwrap();
        assert_eq!(bal, 0);
    }

    #[test]
    fn with_mut_updates() {
        let h = insert(test_account()).unwrap();
        with_mut(h, |acc| {
            acc.state.balance = 999;
            Ok(())
        })
        .unwrap();
        let bal = with(h, |acc| Ok(acc.state.balance)).unwrap();
        assert_eq!(bal, 999);
    }

    #[test]
    fn remove_invalidates() {
        let h = insert(test_account()).unwrap();
        remove(h).unwrap();
        assert_eq!(with(h, |_| Ok(())), Err(KMS_ERR_INVALID_HANDLE));
    }

    #[test]
    fn invalid_handle() {
        assert_eq!(with(999_999, |_| Ok(())), Err(KMS_ERR_INVALID_HANDLE));
    }
}
