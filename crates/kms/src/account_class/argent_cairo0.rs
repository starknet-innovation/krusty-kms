//! Argent Cairo 0 accounts: a proxy class deployed in front of an
//! implementation class and initialised with the owner key and a guardian.
//!
//! The proxy is the **deployment** class: it fixes the address, with the
//! implementation class hash as the first constructor argument. The
//! implementation classes are what those accounts run (until they upgrade to
//! a Cairo 1 class) and are never deployed with directly.
//!
//! Class hashes and version labels come from Argent X's own account
//! constants (see [`super::ARGENT_X_CONSTANTS_SOURCE`]).

use super::registry::{
    AccountFamily, ConstructorShape, KnownAccountClass, ARGENT_X_CONSTANTS_SOURCE, DEPLOYMENT_ONLY,
    IMPLEMENTATION_ONLY,
};
use starknet_types_core::felt::Felt;

/// The Argent Cairo 0 proxy pattern.
pub struct ArgentCairo0;

impl ArgentCairo0 {
    /// Argent Cairo 0 proxy class hash: the deployment class.
    pub const PROXY_CLASS_HASH: &str =
        "0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918";

    /// Implementation v0.2.4 (published by Argent as 0.2.3.1).
    pub const IMPL_CLASS_HASH_V024: &str =
        "0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2";

    /// Implementation v0.2.3.
    pub const IMPL_CLASS_HASH_V023: &str =
        "0x01a7820094feaf82d53f53f214b81292d717e7bb9a92bb2488092cd306f3993f";

    /// Implementation v0.2.2.
    pub const IMPL_CLASS_HASH_V022: &str =
        "0x03e327de1c40540b98d05cbcb13552008e36f0ec8d61d46956d2f9752c294328";

    /// Implementation v0.2.1.
    pub const IMPL_CLASS_HASH_V021: &str =
        "0x07e28fb0161d10d1cf7fe1f13e7ca57bce062731a3bd04494dfd2d0412699727";

    /// `selector("initialize")`: the proxy constructor forwards to it.
    pub const INITIALIZE_SELECTOR: &str =
        "0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463";

    /// The proxy (deployment) class hash.
    pub fn proxy_class_hash() -> Felt {
        static_felt(Self::PROXY_CLASS_HASH)
    }

    /// `selector("initialize")` as a felt.
    pub fn initialize_selector() -> Felt {
        static_felt(Self::INITIALIZE_SELECTOR)
    }

    /// Known implementation classes, newest first: `(class hash, version)`.
    pub fn known_implementations() -> Vec<(Felt, &'static str)> {
        vec![
            (static_felt(Self::IMPL_CLASS_HASH_V024), "0.2.4"),
            (static_felt(Self::IMPL_CLASS_HASH_V023), "0.2.3"),
            (static_felt(Self::IMPL_CLASS_HASH_V022), "0.2.2"),
            (static_felt(Self::IMPL_CLASS_HASH_V021), "0.2.1"),
        ]
    }

    /// Whether `class_hash` is a known Cairo 0 implementation.
    pub fn is_known_implementation(class_hash: &Felt) -> bool {
        Self::known_implementations()
            .iter()
            .any(|(known, _)| known == class_hash)
    }

    /// Proxy constructor calldata for a Starknet-key owner with no guardian:
    /// `[implementation, selector("initialize"), 2, public_key, 0]`.
    pub fn constructor_calldata(implementation: &Felt, public_key: &Felt) -> Vec<Felt> {
        Self::constructor_calldata_with_guardian(implementation, public_key, &Felt::ZERO)
    }

    /// Proxy constructor calldata with a guardian key (zero for none):
    /// `[implementation, selector("initialize"), 2, public_key, guardian]`.
    /// A non-zero guardian is not derived from the seed; this shape verifies
    /// a known account rather than enumerating candidates.
    pub fn constructor_calldata_with_guardian(
        implementation: &Felt,
        public_key: &Felt,
        guardian: &Felt,
    ) -> Vec<Felt> {
        vec![
            *implementation,
            Self::initialize_selector(),
            Felt::TWO,
            *public_key,
            *guardian,
        ]
    }

    /// Registry entries: the proxy as deployment class, the implementations
    /// as implementation classes.
    pub fn known_classes() -> Vec<KnownAccountClass> {
        let mut classes = vec![KnownAccountClass::new(
            AccountFamily::Argent,
            Self::proxy_class_hash(),
            "proxy",
            "Argent Cairo 0 proxy",
            DEPLOYMENT_ONLY,
            Some(ConstructorShape::ArgentCairo0Proxy),
            ARGENT_X_CONSTANTS_SOURCE,
        )];
        classes.extend(
            Self::known_implementations()
                .into_iter()
                .map(|(class_hash, version)| {
                    KnownAccountClass::new(
                        AccountFamily::Argent,
                        class_hash,
                        version,
                        &format!("Argent Cairo 0 account v{version}"),
                        IMPLEMENTATION_ONLY,
                        None,
                        ARGENT_X_CONSTANTS_SOURCE,
                    )
                }),
        );
        classes
    }
}

fn static_felt(hex: &str) -> Felt {
    Felt::from_hex(hex).expect("static Argent Cairo 0 constant")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_class::ClassRole;

    #[test]
    fn initialize_selector_is_the_starknet_keccak_of_the_name() {
        let expected = starknet_rust_core::utils::get_selector_from_name("initialize").unwrap();
        assert_eq!(
            format!("{:#x}", ArgentCairo0::initialize_selector()),
            format!("{expected:#x}")
        );
    }

    #[test]
    fn constructor_calldata_has_the_proxy_shape() {
        let implementation = Felt::from(7u64);
        let pk = Felt::from(42u64);
        assert_eq!(
            ArgentCairo0::constructor_calldata(&implementation, &pk),
            vec![
                implementation,
                ArgentCairo0::initialize_selector(),
                Felt::TWO,
                pk,
                Felt::ZERO
            ]
        );
    }

    #[test]
    fn known_implementations_are_unique_and_recognised() {
        let impls = ArgentCairo0::known_implementations();
        assert_eq!(impls.len(), 4);
        for (hash, _) in &impls {
            assert!(ArgentCairo0::is_known_implementation(hash));
            assert_ne!(*hash, ArgentCairo0::proxy_class_hash());
        }
        assert!(!ArgentCairo0::is_known_implementation(
            &ArgentCairo0::proxy_class_hash()
        ));
    }

    #[test]
    fn registry_entries_cover_proxy_and_every_implementation() {
        let classes = ArgentCairo0::known_classes();
        assert_eq!(classes.len(), 5);
        assert!(classes.iter().all(|c| c.family == AccountFamily::Argent));
        assert_eq!(
            classes
                .iter()
                .filter(|c| c.roles == [ClassRole::Deployment])
                .count(),
            1
        );
    }
}
