//! Argent account preset and its version-dependent constructor layouts.

use super::AccountClass;
use crate::account::calculate_contract_address;
use krusty_kms_common::serialization::serialize_cairo_none;
use krusty_kms_common::{KmsError, Result};
use starknet_types_core::felt::Felt;

/// Constructor calldata layout of an Argent account class.
///
/// Argent changed its constructor signature between releases, so the calldata
/// (and therefore the counterfactual address) depends on the class hash:
///
/// | Class           | Cairo constructor                           | Calldata        |
/// |-----------------|---------------------------------------------|-----------------|
/// | v0.3.0 / v0.3.1 | `(owner: felt252, guardian: felt252)`       | `[owner, 0]`    |
/// | v0.4.0 / v0.5.0 | `(owner: Signer, guardian: Option<Signer>)` | `[0, owner, 1]` |
///
/// In v0.4.0 and v0.5.0 `Signer::Starknet` is enum variant `0` and Cairo
/// serialises `Option::None` as the tag `1`.
///
/// The calldata above is the guardian-less shape a seed can reproduce. With a
/// Starknet-key guardian the shapes are `[owner, guardian]` and
/// `[0, owner, 0, 0, guardian]` ([`Self::constructor_calldata_with_guardian`]);
/// [`Self::decode`] reads either back from on-chain calldata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgentConstructorLayout {
    /// `constructor(owner: felt252, guardian: felt252)` (v0.3.0, v0.3.1).
    OwnerGuardianFelts,
    /// `constructor(owner: Signer, guardian: Option<Signer>)` (v0.4.0, v0.5.0).
    SignerWithOptionalGuardian,
}

impl ArgentConstructorLayout {
    /// Constructor calldata for a Starknet-key owner with no guardian: the
    /// one shape a seed reproduces without knowing the address.
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

    /// Constructor calldata for a Starknet-key owner **with** a Starknet-key
    /// guardian: `[owner, guardian]` for v0.3.x and
    /// `[0, owner, 0, 0, guardian]` for v0.4.0+ (`Signer::Starknet` owner,
    /// `Option::Some(Signer::Starknet)` guardian).
    ///
    /// The guardian is per-account and not derived from the seed, so this
    /// shape cannot be enumerated by discovery. It verifies an account whose
    /// address is already known: take the guardian from that account's
    /// `DEPLOY_ACCOUNT` calldata and compare the reproduced address. Only the
    /// deploy-time guardian fixes the address; an account's current guardian
    /// can have been changed or removed since, and reproduces nothing.
    ///
    /// A zero guardian means "no guardian" and yields
    /// [`Self::constructor_calldata`]. v0.4.0+ guardians are `NonZero`, so a
    /// literal `[0, owner, 0, 0, 0]` could never deploy.
    pub fn constructor_calldata_with_guardian(
        self,
        public_key: &Felt,
        guardian: &Felt,
    ) -> Vec<Felt> {
        match self {
            _ if *guardian == Felt::ZERO => self.constructor_calldata(public_key),
            Self::OwnerGuardianFelts => vec![*public_key, *guardian],
            // Some(Signer::Starknet(g)): Option tag 0, Signer variant 0, key.
            Self::SignerWithOptionalGuardian => {
                vec![Felt::ZERO, *public_key, Felt::ZERO, Felt::ZERO, *guardian]
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
    /// Argent Account class hash (Cairo 1, v0.4.0). The default preset.
    pub const CLASS_HASH: &str =
        "0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f";

    /// Argent Account class hash (Cairo 1, v0.5.0). Same constructor as
    /// v0.4.0: `(owner: Signer, guardian: Option<Signer>)`.
    pub const CLASS_HASH_V050: &str =
        "0x073414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2";

    /// Argent Account class hash (Cairo 1, v0.3.1).
    pub const CLASS_HASH_V031: &str =
        "0x029927c8af6bccf3f6fda035981e765a7bdbf18a2dc0d630494f8758aa908e2b";

    /// Argent Account class hash (Cairo 1, v0.3.0).
    pub const CLASS_HASH_V030: &str =
        "0x01a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003";

    /// Known Argent Cairo 1 classes: class hash, version label, and the
    /// constructor layout that class deserialises.
    ///
    /// The single table every other accessor derives from, newest first. A new
    /// Argent class is added here, with its layout, and nothing else needs to
    /// know: [`Self::known_class_hashes`] and [`Self::layout_for_class_hash`]
    /// read it, and callers that need the labels (account discovery) consume it
    /// directly rather than restating the mapping.
    pub fn known_classes() -> Vec<(Felt, &'static str, ArgentConstructorLayout)> {
        vec![
            (
                static_class_hash(Self::CLASS_HASH_V050),
                "v0.5.0",
                ArgentConstructorLayout::SignerWithOptionalGuardian,
            ),
            (
                static_class_hash(Self::CLASS_HASH),
                "v0.4.0",
                ArgentConstructorLayout::SignerWithOptionalGuardian,
            ),
            (
                static_class_hash(Self::CLASS_HASH_V031),
                "v0.3.1",
                ArgentConstructorLayout::OwnerGuardianFelts,
            ),
            (
                static_class_hash(Self::CLASS_HASH_V030),
                "v0.3.0",
                ArgentConstructorLayout::OwnerGuardianFelts,
            ),
        ]
    }

    /// Class hashes accepted for Argent Cairo 1 deployments.
    pub fn known_class_hashes() -> Vec<Felt> {
        Self::known_classes()
            .into_iter()
            .map(|(class_hash, _, _)| class_hash)
            .collect()
    }

    /// Constructor layout of a known Argent class hash, if recognised.
    pub fn layout_for_class_hash(class_hash: &Felt) -> Option<ArgentConstructorLayout> {
        Self::known_classes()
            .into_iter()
            .find(|(known, _, _)| known == class_hash)
            .map(|(_, _, layout)| layout)
    }

    /// The default Argent class (v0.4.0), the class the on-chain vector in
    /// this crate's tests pins. v0.5.0 is a known class too and is selected
    /// with [`Self::try_with_class_hash`]; the default is unchanged so derived
    /// addresses stay stable across releases.
    pub fn new() -> Self {
        Self::with_class_hash_and_layout(
            static_class_hash(Self::CLASS_HASH),
            ArgentConstructorLayout::SignerWithOptionalGuardian,
        )
    }

    /// Create with a custom class hash.
    ///
    /// Known Argent class hashes select their constructor layout automatically.
    /// An unknown class hash assumes the current (v0.4.0) layout, which yields
    /// an undeployable address if that class takes a different constructor
    /// (unverifiable from the hash alone);
    /// prefer [`Self::try_with_class_hash`], or state the layout explicitly
    /// with [`Self::with_class_hash_and_layout`].
    #[deprecated(
        note = "unknown class hashes silently assume the v0.4.0 layout; use try_with_class_hash"
    )]
    pub fn with_class_hash(class_hash: Felt) -> Self {
        let layout = Self::layout_for_class_hash(&class_hash)
            .unwrap_or(ArgentConstructorLayout::SignerWithOptionalGuardian);
        Self::with_class_hash_and_layout(class_hash, layout)
    }

    /// Create with a class hash whose constructor layout is known.
    ///
    /// Returns [`KmsError::InvalidClassHash`] for a class hash that is not a
    /// recognised Argent class. Argent has already changed its constructor
    /// once (v0.3.x to v0.4.0), so the layout of an unrecognised class is
    /// unverified: it may match v0.4.0, or it may reject the guessed calldata
    /// and leave an address that can never be deployed. Callers that accept a
    /// class hash from outside cannot tell which, so they must reject it. Use
    /// [`Self::with_class_hash_and_layout`] to opt into a specific layout for
    /// a class this crate does not know.
    pub fn try_with_class_hash(class_hash: Felt) -> Result<Self> {
        let layout = Self::layout_for_class_hash(&class_hash).ok_or_else(|| {
            KmsError::InvalidClassHash(format!(
                "unknown Argent class hash {class_hash:#x}: no known constructor layout"
            ))
        })?;
        Ok(Self::with_class_hash_and_layout(class_hash, layout))
    }

    /// Create with an explicit class hash and constructor layout.
    pub fn with_class_hash_and_layout(class_hash: Felt, layout: ArgentConstructorLayout) -> Self {
        Self { class_hash, layout }
    }

    /// Constructor calldata layout used by this preset.
    pub fn constructor_layout(&self) -> ArgentConstructorLayout {
        self.layout
    }

    /// Address of an account deployed with `public_key` as owner and a
    /// Starknet-key `guardian`, salted with the public key as Argent does;
    /// calldata per [`ArgentConstructorLayout::constructor_calldata_with_guardian`].
    ///
    /// Discovery cannot produce this address (the guardian is not in the
    /// seed); use it to verify an account whose address and deploy-time
    /// guardian are known. A zero guardian gives the guardian-less address.
    pub fn calculate_address_with_guardian(
        &self,
        public_key: &Felt,
        guardian: &Felt,
    ) -> Result<Felt> {
        let calldata = self
            .layout
            .constructor_calldata_with_guardian(public_key, guardian);
        calculate_contract_address(public_key, &self.class_hash, &calldata, &Felt::ZERO)
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
            let argent = ArgentAccount::try_with_class_hash(Felt::from_hex(hash).unwrap()).unwrap();
            assert_eq!(
                argent.constructor_layout(),
                ArgentConstructorLayout::OwnerGuardianFelts
            );
            assert_eq!(argent.build_constructor_calldata(&pk), vec![pk, Felt::ZERO]);
        }
    }

    #[test]
    fn test_argent_unknown_class_hash_is_rejected() {
        let custom = Felt::from(0xabcdu64);
        assert_eq!(ArgentAccount::layout_for_class_hash(&custom), None);
        match ArgentAccount::try_with_class_hash(custom) {
            Err(KmsError::InvalidClassHash(msg)) => assert!(msg.contains("abcd"), "{msg}"),
            Err(other) => panic!("expected InvalidClassHash, got {other}"),
            Ok(_) => panic!("unknown class hash must be rejected"),
        }
    }

    #[test]
    fn test_argent_try_with_class_hash_accepts_known_classes() {
        for (hash, expected) in [
            (
                ArgentAccount::CLASS_HASH_V050,
                ArgentConstructorLayout::SignerWithOptionalGuardian,
            ),
            (
                ArgentAccount::CLASS_HASH,
                ArgentConstructorLayout::SignerWithOptionalGuardian,
            ),
            (
                ArgentAccount::CLASS_HASH_V031,
                ArgentConstructorLayout::OwnerGuardianFelts,
            ),
            (
                ArgentAccount::CLASS_HASH_V030,
                ArgentConstructorLayout::OwnerGuardianFelts,
            ),
        ] {
            let argent = ArgentAccount::try_with_class_hash(Felt::from_hex(hash).unwrap()).unwrap();
            assert_eq!(argent.constructor_layout(), expected);
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_argent_deprecated_with_class_hash_still_guesses_latest_layout() {
        // Pins the documented behaviour of the deprecated constructor: it
        // still assumes v0.4.0 for an unknown class. Remove with the function.
        let argent = ArgentAccount::with_class_hash(Felt::from(0xabcdu64));
        assert_eq!(
            argent.constructor_layout(),
            ArgentConstructorLayout::SignerWithOptionalGuardian
        );
    }

    #[test]
    fn test_argent_explicit_layout_overrides_for_unknown_class() {
        let custom = Felt::from(0xabcdu64);
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
