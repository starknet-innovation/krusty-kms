//! A zeroizing wrapper for secret `Felt` values.
//!
//! `SecretFelt` wraps a `Felt` and ensures the underlying memory is
//! overwritten with zeros when the value is dropped, preventing private
//! key material from lingering in memory.

use core::ops::Deref;
use starknet_types_core::felt::Felt;
use zeroize::Zeroize;

/// A `Felt` that holds secret key material and is zeroized on drop.
///
/// This wrapper ensures that secret scalar values (private keys, seeds) are
/// overwritten with zeros when they go out of scope, preventing them from
/// lingering in memory after use.
///
/// # Security
///
/// - `Debug` output is redacted to prevent accidental logging of secrets.
/// - `LowerHex` is delegated to `Felt` for intentional serialization (e.g.,
///   `private_key_hex()` methods).
/// - `Drop` uses a volatile write to prevent the compiler from optimizing
///   away the zeroing.
#[derive(Clone)]
pub struct SecretFelt(Felt);

impl SecretFelt {
    /// Create a new `SecretFelt` from a `Felt`.
    pub fn new(felt: Felt) -> Self {
        Self(felt)
    }
}

impl Deref for SecretFelt {
    type Target = Felt;

    fn deref(&self) -> &Felt {
        &self.0
    }
}

impl From<Felt> for SecretFelt {
    fn from(felt: Felt) -> Self {
        Self(felt)
    }
}

impl PartialEq for SecretFelt {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<Felt> for SecretFelt {
    fn eq(&self, other: &Felt) -> bool {
        self.0 == *other
    }
}

impl Eq for SecretFelt {}

impl core::fmt::Debug for SecretFelt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretFelt(***)")
    }
}

impl core::fmt::LowerHex for SecretFelt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self.0, f)
    }
}

impl Zeroize for SecretFelt {
    fn zeroize(&mut self) {
        // Use a volatile write to prevent the compiler from optimizing
        // away the zeroing. This is the same approach used by the `zeroize`
        // crate for opaque types.
        unsafe {
            core::ptr::write_volatile(&mut self.0, Felt::ZERO);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for SecretFelt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_felt_deref() {
        let secret = SecretFelt::new(Felt::from(42u64));
        assert_eq!(*secret, Felt::from(42u64));
    }

    #[test]
    fn test_secret_felt_partial_eq() {
        let a = SecretFelt::new(Felt::from(42u64));
        let b = SecretFelt::new(Felt::from(42u64));
        assert_eq!(a, b);
        assert_eq!(a, Felt::from(42u64));
    }

    #[test]
    fn test_secret_felt_debug_redacted() {
        let secret = SecretFelt::new(Felt::from(42u64));
        let debug = format!("{:?}", secret);
        assert_eq!(debug, "SecretFelt(***)");
        assert!(!debug.contains("42"));
    }

    #[test]
    fn test_secret_felt_hex_format() {
        let secret = SecretFelt::new(Felt::from(42u64));
        let hex = format!("{:#x}", secret);
        assert_eq!(hex, "0x2a");
    }

    #[test]
    fn test_secret_felt_clone() {
        let a = SecretFelt::new(Felt::from(42u64));
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_secret_felt_from() {
        let secret: SecretFelt = Felt::from(99u64).into();
        assert_eq!(*secret, Felt::from(99u64));
    }

    #[test]
    fn test_secret_felt_zeroize() {
        let mut secret = SecretFelt::new(Felt::from(42u64));
        secret.zeroize();
        assert_eq!(*secret, Felt::ZERO);
    }
}
