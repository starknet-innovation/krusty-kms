//! Argent account preset and its version-dependent constructor layouts.

use super::AccountClass;
use krusty_kms_common::serialization::serialize_cairo_none;
use starknet_types_core::felt::Felt;

/// Constructor calldata layout of an Argent account class.
///
/// Argent changed its constructor signature between releases, so the calldata
/// (and therefore the counterfactual address) depends on the class hash:
///
/// | Class           | Cairo constructor                           | Calldata        |
/// |-----------------|---------------------------------------------|-----------------|
/// | v0.3.0 / v0.3.1 | `(owner: felt252, guardian: felt252)`       | `[owner, 0]`    |
/// | v0.4.0          | `(owner: Signer, guardian: Option<Signer>)` | `[0, owner, 1]` |
///
/// In v0.4.0 `Signer::Starknet` is enum variant `0` and Cairo serialises
/// `Option::None` as the tag `1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgentConstructorLayout {
    /// `constructor(owner: felt252, guardian: felt252)` (v0.3.0, v0.3.1).
    OwnerGuardianFelts,
    /// `constructor(owner: Signer, guardian: Option<Signer>)` (v0.4.0).
    SignerWithOptionalGuardian,
}

impl ArgentConstructorLayout {
    /// Constructor calldata for a Starknet-key owner with no guardian.
    pub fn constructor_calldata(self, public_key: &Felt) -> Vec<Felt> {
        match self {
            Self::OwnerGuardianFelts => vec![*public_key, Felt::ZERO],
            Self::SignerWithOptionalGuardian => {
                let mut calldata = vec![Felt::ZERO, *public_key];
                calldata.extend(serialize_cairo_none());
                calldata
            }
        }
    }
}

/// Argent account contract preset (Cairo 1).
///
/// Standard Argent accounts deploy with `salt = public_key`, a Starknet-key
/// owner and no guardian. The constructor calldata depends on the class
/// version; see [`ArgentConstructorLayout`].
pub struct ArgentAccount {
    class_hash: Felt,
    layout: ArgentConstructorLayout,
}

impl ArgentAccount {
    /// Argent Account class hash (Cairo 1, v0.4.0).
    pub const CLASS_HASH: &str =
        "0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f";

    /// Argent Account class hash (Cairo 1, v0.3.1).
    pub const CLASS_HASH_V031: &str =
        "0x029927c8af6bccf3f6fda035981e765a7bdbf18a2dc0d630494f8758aa908e2b";

    /// Argent Account class hash (Cairo 1, v0.3.0).
    pub const CLASS_HASH_V030: &str =
        "0x01a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003";

    /// Class hashes accepted for Argent Cairo 1 deployments.
    pub fn known_class_hashes() -> Vec<Felt> {
        [
            Self::CLASS_HASH,
            Self::CLASS_HASH_V031,
            Self::CLASS_HASH_V030,
        ]
        .into_iter()
        .map(static_class_hash)
        .collect()
    }

    /// Constructor layout of a known Argent class hash, if recognised.
    pub fn layout_for_class_hash(class_hash: &Felt) -> Option<ArgentConstructorLayout> {
        if *class_hash == static_class_hash(Self::CLASS_HASH) {
            Some(ArgentConstructorLayout::SignerWithOptionalGuardian)
        } else if *class_hash == static_class_hash(Self::CLASS_HASH_V031)
            || *class_hash == static_class_hash(Self::CLASS_HASH_V030)
        {
            Some(ArgentConstructorLayout::OwnerGuardianFelts)
        } else {
            None
        }
    }

    /// Latest supported Argent class (v0.4.0).
    pub fn new() -> Self {
        Self::with_class_hash_and_layout(
            static_class_hash(Self::CLASS_HASH),
            ArgentConstructorLayout::SignerWithOptionalGuardian,
        )
    }

    /// Create with a custom class hash.
    ///
    /// Known Argent class hashes select their constructor layout automatically.
    /// An unknown class hash assumes the current (v0.4.0) layout; use
    /// [`Self::with_class_hash_and_layout`] to state it explicitly.
    pub fn with_class_hash(class_hash: Felt) -> Self {
        let layout = Self::layout_for_class_hash(&class_hash)
            .unwrap_or(ArgentConstructorLayout::SignerWithOptionalGuardian);
        Self::with_class_hash_and_layout(class_hash, layout)
    }

    /// Create with an explicit class hash and constructor layout.
    pub fn with_class_hash_and_layout(class_hash: Felt, layout: ArgentConstructorLayout) -> Self {
        Self { class_hash, layout }
    }

    /// Constructor calldata layout used by this preset.
    pub fn constructor_layout(&self) -> ArgentConstructorLayout {
        self.layout
    }
}

fn static_class_hash(hex: &str) -> Felt {
    Felt::from_hex(hex).expect("static Argent class hash")
}

impl Default for ArgentAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountClass for ArgentAccount {
    fn class_hash(&self) -> Felt {
        self.class_hash
    }

    fn build_constructor_calldata(&self, public_key: &Felt) -> Vec<Felt> {
        self.layout.constructor_calldata(public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argent_v040_calldata_encodes_guardian_none_tag() {
        let argent = ArgentAccount::new();
        let pk = Felt::from(42u64);
        let cd = argent.build_constructor_calldata(&pk);
        // `Signer::Starknet` is variant 0; `Option::None` serialises as tag 1.
        assert_eq!(cd, vec![Felt::ZERO, pk, Felt::ONE]);
        assert_eq!(cd[2..], serialize_cairo_none()[..]);
        assert_eq!(
            argent.constructor_layout(),
            ArgentConstructorLayout::SignerWithOptionalGuardian
        );
    }

    #[test]
    fn test_argent_v03_calldata_is_owner_guardian_felts() {
        let pk = Felt::from(42u64);
        for hash in [
            ArgentAccount::CLASS_HASH_V030,
            ArgentAccount::CLASS_HASH_V031,
        ] {
            let argent = ArgentAccount::with_class_hash(Felt::from_hex(hash).unwrap());
            assert_eq!(
                argent.constructor_layout(),
                ArgentConstructorLayout::OwnerGuardianFelts
            );
            assert_eq!(argent.build_constructor_calldata(&pk), vec![pk, Felt::ZERO]);
        }
    }

    #[test]
    fn test_argent_unknown_class_hash_defaults_to_latest_layout() {
        let custom = Felt::from(0xabcdu64);
        assert_eq!(ArgentAccount::layout_for_class_hash(&custom), None);
        let argent = ArgentAccount::with_class_hash(custom);
        assert_eq!(
            argent.constructor_layout(),
            ArgentConstructorLayout::SignerWithOptionalGuardian
        );
        let explicit = ArgentAccount::with_class_hash_and_layout(
            custom,
            ArgentConstructorLayout::OwnerGuardianFelts,
        );
        assert_eq!(
            explicit.constructor_layout(),
            ArgentConstructorLayout::OwnerGuardianFelts
        );
    }
}
