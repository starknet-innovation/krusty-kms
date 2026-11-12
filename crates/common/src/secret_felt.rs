//! A zeroizing wrapper for secret `Felt` values.
//!
//! `SecretFelt` wraps a `Felt` and ensures the underlying memory is
//! overwritten with zeros when the value is dropped, preventing private
//! key material from lingering in memory.

use starknet_types_core::felt::Felt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A `Felt` that holds secret key material and is zeroized on drop.
///
/// This wrapper ensures that secret scalar values (private keys, seeds) are
/// overwritten with zeros when they go out of scope, preventing them from
/// lingering in memory after use.
///
/// # Security
///
/// - All access to the inner `Felt` must go through [`Self::expose_secret`], making
///   every secret-access point explicit and greppable.
/// - `Debug` output is redacted to prevent accidental logging of secrets.
/// - Hex serialization requires the explicit [`Self::expose_secret_hex`] escape hatch.
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
    /// whenever possible. The returned buffer zeroizes itself on drop; callers
    /// that copy it into a plain `String` own that copy's hygiene.
    pub fn expose_secret_hex(&self) -> zeroize::Zeroizing<String> {
        // Same output as `{:#x}`, but `Felt`'s `LowerHex` builds an
        // intermediate `String` that is never wiped. Capacity 66 means no
        // reallocation leaves a partial copy behind.
        let bytes = zeroize::Zeroizing::new(self.0.to_bytes_be());
        let mut out = zeroize::Zeroizing::new(String::with_capacity(66));
        out.push_str("0x");
        let mut started = false;
        for nibble in bytes.iter().flat_map(|b| [b >> 4, b & 0xf]) {
            started |= nibble != 0;
            if started {
                out.push(char::from_digit(u32::from(nibble), 16).expect("nibble < 16"));
            }
        }
        if !started {
            out.push('0');
        }
        out
    }
}

impl From<Felt> for SecretFelt {
    fn from(felt: Felt) -> Self {
        Self(felt)
    }
}

impl PartialEq for SecretFelt {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time compare of big-endian encodings to avoid timing leaks
        // when checking secret equality (e.g. key verification).
        let a = zeroize::Zeroizing::new(self.0.to_bytes_be());
        let b = zeroize::Zeroizing::new(other.0.to_bytes_be());
        bool::from(a.ct_eq(&*b))
    }
}

impl PartialEq<Felt> for SecretFelt {
    fn eq(&self, other: &Felt) -> bool {
        let a = zeroize::Zeroizing::new(self.0.to_bytes_be());
        let b = zeroize::Zeroizing::new(other.to_bytes_be());
        bool::from(a.ct_eq(&*b))
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
        assert_eq!(hex.as_str(), "0x2a");
    }

    #[test]
    fn test_secret_felt_hex_matches_lower_hex() {
        for felt in [
            Felt::ZERO,
            Felt::ONE,
            Felt::from(0x10u64),
            Felt::MAX,
            Felt::from_hex("0x7baa040a82762f75cb1fdd42cc04edbe20aae62899dd01f2cc93c169b594640")
                .unwrap(),
        ] {
            let hex = SecretFelt::new(felt).expose_secret_hex();
            assert_eq!(hex.as_str(), format!("{felt:#x}"));
        }
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
