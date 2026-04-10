//! A zeroizing wrapper for secret `Felt` values.
//!
//! `SecretFelt` wraps a `Felt` and ensures the underlying memory is
//! overwritten with zeros when the value is dropped, preventing private
//! key material from lingering in memory.

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
/// - All access to the inner `Felt` must go through [`expose_secret()`], making
///   every secret-access point explicit and greppable.
/// - `Debug` output is redacted to prevent accidental logging of secrets.
/// - Hex serialization requires the explicit [`expose_secret_hex()`] escape hatch.
/// - `Drop` uses a volatile write to prevent the compiler from optimizing
///   away the zeroing.
// Clone is needed by TongoKeyPair; note that cloning duplicates the secret.
#[derive(Clone)]
pub struct SecretFelt(Felt);

impl SecretFelt {
    /// Create a new `SecretFelt` from a `Felt`.
    pub fn new(felt: Felt) -> Self {
        Self(felt)
    }

    /// Access the secret value. Every call site is explicit and greppable.
    pub fn expose_secret(&self) -> &Felt {
        &self.0
    }

    /// Export the secret value as a hex string.
    ///
    /// This is an intentional escape hatch for boundaries that must serialize
    /// private material. Prefer keeping secrets as `SecretFelt` or `&Felt`
    /// whenever possible.
    pub fn expose_secret_hex(&self) -> String {
        format!("{:#x}", self.0)
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

impl Zeroize for SecretFelt {
    fn zeroize(&mut self) {
        // Use a volatile write to prevent the compiler from optimizing
        // away the zeroing. This is the same approach used by the `zeroize`
        // crate for opaque types.
        unsafe {
            core::ptr::write_volatile(&raw mut self.0, Felt::ZERO);
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
    fn test_secret_felt_expose_secret() {
        let secret = SecretFelt::new(Felt::from(42u64));
        assert_eq!(*secret.expose_secret(), Felt::from(42u64));
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
    fn test_secret_felt_hex_format_requires_explicit_escape_hatch() {
        let secret = SecretFelt::new(Felt::from(42u64));
        let hex = secret.expose_secret_hex();
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
        assert_eq!(*secret.expose_secret(), Felt::from(99u64));
    }

    #[test]
    fn test_secret_felt_zeroize() {
        let mut secret = SecretFelt::new(Felt::from(42u64));
        secret.zeroize();
        assert_eq!(*secret.expose_secret(), Felt::ZERO);
    }
}
