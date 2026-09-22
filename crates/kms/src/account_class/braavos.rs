//! Braavos account preset: base (deployment) and account (implementation)
//! classes.
//!
//! Braavos deploys every account with a **base** class whose constructor takes
//! `[public_key]`. The target implementation travels in the deploy
//! *signature*, never in `class_hash`; the base class validates it and
//! swaps itself out with `replace_class_syscall` in the same transaction. So
//! the address is fixed by the base class alone, while the class an account
//! runs today (`starknet_getClassHashAt`) is always an implementation class.
//! Deriving from an implementation class can never reproduce a real account.
//!
//! Class hashes are taken from the `README.md` of
//! <https://github.com/myBraavos/braavos-account-cairo> at each release tag.

use super::registry::{
    AccountFamily, ClassRole, ConstructorShape, KnownAccountClass, DEPLOYMENT_ONLY,
    IMPLEMENTATION_ONLY,
};
use super::AccountClass;
use krusty_kms_common::{KmsError, Result};
use starknet_types_core::felt::Felt;

const README_V100: &str =
    "https://github.com/myBraavos/braavos-account-cairo/blob/v1.0.0/README.md";
const README_V110: &str =
    "https://github.com/myBraavos/braavos-account-cairo/blob/v1.1.0/README.md";
const README_V120: &str =
    "https://github.com/myBraavos/braavos-account-cairo/blob/v1.2.0/README.md";

/// Braavos account contract preset.
///
/// Constructor: `(public_key)`. Addresses are derived from a base class, see
/// the module documentation.
pub struct BraavosAccount {
    class_hash: Felt,
}

impl BraavosAccount {
    /// Braavos Base Account class hash for v1.1.0 and v1.2.0: the current
    /// deployment class. Every Braavos account created since v1.1.0 derives
    /// its address from this hash.
    pub const CLASS_HASH: &str =
        "0x03d16c7a9a60b0593bd202f660a28c5d76e0403601d9ccc7e4fa253b6a70c201";

    /// Braavos Base Account class hash for v1.0.0. Accounts created under
    /// v1.0.0 derive their address from this hash and from nothing else.
    pub const BASE_CLASS_HASH_V100: &str =
        "0x013bfe114fb1cf405bfc3a7f8dbe2d91db146c17521d40dcf57e16d6b59fa8e6";

    /// Braavos Account (implementation) class hash for v1.0.0. Not a
    /// deployment class: it appears in deploy signatures and as the class
    /// accounts run, never as a `DEPLOY_ACCOUNT` `class_hash`. Kept under its
    /// historical name.
    pub const LEGACY_CLASS_HASH: &str =
        "0x00816dd0297efc55dc1e7559020a3a825e81ef734b558f03c83325d4da7e6253";

    /// Braavos Account (implementation) class hash for v1.1.0.
    pub const ACCOUNT_CLASS_HASH_V110: &str =
        "0x02c8c7e6fbcfb3e8e15a46648e8914c6aa1fc506fc1e7fb3d1e19630716174bc";

    /// Braavos Account (implementation) class hash for v1.2.0, the class most
    /// Braavos accounts run today.
    pub const ACCOUNT_CLASS_HASH_V120: &str =
        "0x03957f9f5a1cbfe918cedc2015c85200ca51a5f7506ecb6de98a5207b759bf8a";

    /// Known Braavos classes with their roles, newest first within each role.
    pub fn known_classes() -> Vec<KnownAccountClass> {
        let class = |hash, version, label, roles, constructor, source| {
            KnownAccountClass::new(
                AccountFamily::Braavos,
                static_class_hash(hash),
                version,
                label,
                roles,
                constructor,
                source,
            )
        };
        vec![
            class(
                Self::CLASS_HASH,
                "1.1.0",
                "Braavos Base Account v1.1.0 and later",
                DEPLOYMENT_ONLY,
                Some(ConstructorShape::PublicKey),
                README_V120,
            ),
            class(
                Self::BASE_CLASS_HASH_V100,
                "1.0.0",
                "Braavos Base Account v1.0.0",
                DEPLOYMENT_ONLY,
                Some(ConstructorShape::PublicKey),
                README_V100,
            ),
            class(
                Self::ACCOUNT_CLASS_HASH_V120,
                "1.2.0",
                "Braavos Account v1.2.0",
                IMPLEMENTATION_ONLY,
                None,
                README_V120,
            ),
            class(
                Self::ACCOUNT_CLASS_HASH_V110,
                "1.1.0",
                "Braavos Account v1.1.0",
                IMPLEMENTATION_ONLY,
                None,
                README_V110,
            ),
            class(
                Self::LEGACY_CLASS_HASH,
                "1.0.0",
                "Braavos Account v1.0.0",
                IMPLEMENTATION_ONLY,
                None,
                README_V100,
            ),
        ]
    }

    /// Base classes accounts are deployed with. Derive addresses from these.
    pub fn deployment_class_hashes() -> Vec<Felt> {
        Self::class_hashes_with_role(ClassRole::Deployment)
    }

    /// Implementation classes accounts run after their upgrade. Accept these
    /// when signing; never derive from them.
    pub fn implementation_class_hashes() -> Vec<Felt> {
        Self::class_hashes_with_role(ClassRole::Implementation)
    }

    /// Whether `class_hash` is a known Braavos implementation class.
    pub fn is_implementation_class_hash(class_hash: &Felt) -> bool {
        Self::implementation_class_hashes().contains(class_hash)
    }

    fn class_hashes_with_role(role: ClassRole) -> Vec<Felt> {
        Self::known_classes()
            .into_iter()
            .filter(|class| class.roles.contains(&role))
            .map(|class| class.class_hash)
            .collect()
    }

    /// The current base class ([`Self::CLASS_HASH`]).
    pub fn new() -> Self {
        Self::with_class_hash(static_class_hash(Self::CLASS_HASH))
    }

    /// Create with an arbitrary class hash, unchecked.
    ///
    /// Prefer [`Self::try_with_class_hash`]: an implementation class hash
    /// derives an address no Braavos deployment can ever produce.
    pub fn with_class_hash(class_hash: Felt) -> Self {
        Self { class_hash }
    }

    /// Create with a known Braavos **deployment** class hash.
    ///
    /// Returns [`KmsError::InvalidClassHash`] for a known implementation class
    /// (the class an upgraded account runs, which never fixes an address) and
    /// for a class hash this crate does not know. Braavos accounts always
    /// upgrade, so a class hash read from the chain is an implementation
    /// class; derive from [`Self::deployment_class_hashes`] instead.
    pub fn try_with_class_hash(class_hash: Felt) -> Result<Self> {
        if Self::deployment_class_hashes().contains(&class_hash) {
            return Ok(Self::with_class_hash(class_hash));
        }
        if Self::is_implementation_class_hash(&class_hash) {
            return Err(KmsError::InvalidClassHash(format!(
                "{class_hash:#x} is a Braavos account implementation class; addresses are \
                 fixed by a base (deployment) class, derive from one of those instead"
            )));
        }
        Err(KmsError::InvalidClassHash(format!(
            "unknown Braavos class hash {class_hash:#x}: not a known base (deployment) class"
        )))
    }
}

fn static_class_hash(hex: &str) -> Felt {
    Felt::from_hex(hex).expect("static Braavos class hash")
}

impl Default for BraavosAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountClass for BraavosAccount {
    fn class_hash(&self) -> Felt {
        self.class_hash
    }

    fn build_constructor_calldata(&self, public_key: &Felt) -> Vec<Felt> {
        vec![*public_key]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felt(hex: &str) -> Felt {
        Felt::from_hex(hex).unwrap()
    }

    #[test]
    fn test_braavos_calldata() {
        let braavos = BraavosAccount::new();
        let pk = Felt::from(42u64);
        assert_eq!(braavos.build_constructor_calldata(&pk), vec![pk]);
        assert_eq!(braavos.class_hash(), felt(BraavosAccount::CLASS_HASH));
    }

    #[test]
    fn deployment_and_implementation_classes_are_disjoint_and_complete() {
        let deployment = BraavosAccount::deployment_class_hashes();
        let implementation = BraavosAccount::implementation_class_hashes();
        assert_eq!(
            deployment,
            vec![
                felt(BraavosAccount::CLASS_HASH),
                felt(BraavosAccount::BASE_CLASS_HASH_V100)
            ]
        );
        assert_eq!(
            implementation,
            vec![
                felt(BraavosAccount::ACCOUNT_CLASS_HASH_V120),
                felt(BraavosAccount::ACCOUNT_CLASS_HASH_V110),
                felt(BraavosAccount::LEGACY_CLASS_HASH)
            ]
        );
        assert!(deployment.iter().all(|hash| !implementation.contains(hash)));
        assert_eq!(
            BraavosAccount::known_classes().len(),
            deployment.len() + implementation.len()
        );
    }

    #[test]
    fn try_with_class_hash_accepts_every_deployment_class() {
        for hash in BraavosAccount::deployment_class_hashes() {
            let account = BraavosAccount::try_with_class_hash(hash).unwrap();
            assert_eq!(account.class_hash(), hash);
        }
    }

    #[test]
    fn try_with_class_hash_rejects_implementation_classes() {
        for hash in BraavosAccount::implementation_class_hashes() {
            match BraavosAccount::try_with_class_hash(hash) {
                Err(KmsError::InvalidClassHash(msg)) => {
                    assert!(msg.contains("implementation class"), "{msg}");
                }
                Err(other) => panic!("expected InvalidClassHash, got {other}"),
                Ok(_) => panic!("implementation class {hash:#x} must be rejected"),
            }
        }
    }

    #[test]
    fn try_with_class_hash_rejects_unknown_classes() {
        match BraavosAccount::try_with_class_hash(Felt::from(0xabcdu64)) {
            Err(KmsError::InvalidClassHash(msg)) => assert!(msg.contains("unknown"), "{msg}"),
            Err(other) => panic!("expected InvalidClassHash, got {other}"),
            Ok(_) => panic!("unknown class hash must be rejected"),
        }
    }

    #[test]
    fn with_class_hash_stays_unchecked_for_custom_classes() {
        let custom = Felt::from(0xabcdu64);
        assert_eq!(BraavosAccount::with_class_hash(custom).class_hash(), custom);
    }
}
