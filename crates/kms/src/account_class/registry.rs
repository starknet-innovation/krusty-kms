//! Registry of known Starknet account classes, labelled by the role each
//! class plays.
//!
//! A class hash plays one of two roles for an account, and callers need to
//! tell them apart:
//!
//! - a **deployment** class fixes the contract address. It is the
//!   `class_hash` of the `DEPLOY_ACCOUNT` transaction and the only class an
//!   address can be derived from;
//! - an **implementation** class is what the account runs after upgrading. It
//!   is what `starknet_getClassHashAt` returns today and what a signer must
//!   accept, but it never fixes an address.
//!
//! Braavos separates the two by design: every account deploys with a base
//! class and upgrades itself to the account implementation inside the same
//! transaction, so no Braavos account runs the class it was deployed with,
//! and deriving from an implementation class can never reproduce a real
//! account. Argent and OpenZeppelin classes play both roles: an account
//! deploys with the class and keeps running it until it upgrades.
//!
//! Every entry was checked against the vendor's public listing named in its
//! `source` field.

use super::argent::ArgentAccount;
use super::argent_cairo0::ArgentCairo0;
use super::braavos::BraavosAccount;
pub use super::constructor_shape::ConstructorShape;
use super::oz_manifest_classes;
use serde::{Serialize, Serializer};
use starknet_types_core::felt::Felt;

/// Where Argent publishes its Cairo 1 account class hashes.
pub(crate) const ARGENT_DEPLOYMENTS_SOURCE: &str =
    "https://github.com/argentlabs/argent-contracts-starknet/blob/main/deployments/account.txt";

/// Where Argent X publishes the Cairo 0 proxy and implementation class hashes.
pub(crate) const ARGENT_X_CONSTANTS_SOURCE: &str = "https://github.com/argentlabs/argent-x/blob/develop/packages/extension/src/shared/account/starknet.constants.ts";

/// Both roles: the class an account deploys with is also the one it runs.
pub(crate) const DEPLOYMENT_AND_IMPLEMENTATION: &[ClassRole] =
    &[ClassRole::Deployment, ClassRole::Implementation];
/// Deployment only: the class fixes the address and is replaced on upgrade.
pub(crate) const DEPLOYMENT_ONLY: &[ClassRole] = &[ClassRole::Deployment];
/// Implementation only: the class is upgraded to and never deployed with.
pub(crate) const IMPLEMENTATION_ONLY: &[ClassRole] = &[ClassRole::Implementation];

/// Account contract family a class belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountFamily {
    OpenZeppelin,
    Argent,
    Braavos,
}

/// Role a class plays for the accounts that use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassRole {
    /// The class an account is deployed with. Fixes the address; derive from it.
    Deployment,
    /// The class an account runs after upgrading. Accept it when signing.
    Implementation,
}

/// A class hash this crate knows, with the role it plays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownAccountClass {
    pub family: AccountFamily,
    #[serde(serialize_with = "serialize_felt_hex")]
    pub class_hash: Felt,
    /// The release the class belongs to, as the vendor labels it (`"0.4.0"`,
    /// `"1.2.0"`, `"proxy"`).
    pub version: String,
    /// Human-readable name (`"Braavos Base Account v1.1.0 and later"`).
    pub label: String,
    /// Roles the class plays; never empty.
    pub roles: Vec<ClassRole>,
    /// Constructor calldata for a seed-derived key. `None` for a class that is
    /// never deployed with, so there is nothing to derive from.
    pub constructor: Option<ConstructorShape>,
    /// Public listing this entry was checked against.
    pub source: String,
}

impl KnownAccountClass {
    pub(crate) fn new(
        family: AccountFamily,
        class_hash: Felt,
        version: &str,
        label: &str,
        roles: &[ClassRole],
        constructor: Option<ConstructorShape>,
        source: &str,
    ) -> Self {
        Self {
            family,
            class_hash,
            version: version.to_string(),
            label: label.to_string(),
            roles: roles.to_vec(),
            constructor,
            source: source.to_string(),
        }
    }

    /// Whether accounts are deployed with this class (it fixes their address).
    pub fn is_deployment_class(&self) -> bool {
        self.roles.contains(&ClassRole::Deployment)
    }

    /// Whether accounts run this class after upgrading (accept it when signing).
    pub fn is_implementation_class(&self) -> bool {
        self.roles.contains(&ClassRole::Implementation)
    }
}

fn serialize_felt_hex<S: Serializer>(felt: &Felt, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("{felt:#x}"))
}

/// Every account class this crate knows, grouped by family.
///
/// The one table the class-hash accessors on [`ArgentAccount`],
/// [`BraavosAccount`] and [`ArgentCairo0`] agree with; the WASM class-hash
/// exports serialise it directly.
pub fn known_account_classes() -> Vec<KnownAccountClass> {
    let mut classes = oz_classes();
    classes.extend(argent_cairo1_classes());
    classes.extend(ArgentCairo0::known_classes());
    classes.extend(BraavosAccount::known_classes());
    classes
}

/// Look a class hash up in the registry.
pub fn lookup_account_class(class_hash: &Felt) -> Option<KnownAccountClass> {
    known_account_classes()
        .into_iter()
        .find(|class| class.class_hash == *class_hash)
}

/// Classes accounts of `family` are deployed with: derive addresses from these.
pub fn deployment_classes(family: AccountFamily) -> Vec<KnownAccountClass> {
    known_account_classes()
        .into_iter()
        .filter(|class| class.family == family && class.is_deployment_class())
        .collect()
}

/// Classes accounts of `family` run today: accept these when signing.
pub fn implementation_classes(family: AccountFamily) -> Vec<KnownAccountClass> {
    known_account_classes()
        .into_iter()
        .filter(|class| class.family == family && class.is_implementation_class())
        .collect()
}

fn oz_classes() -> Vec<KnownAccountClass> {
    // The manifest is embedded in the crate and its parse is pinned by the
    // account_class tests, so a failure here is a build defect, not an input.
    oz_manifest_classes()
        .unwrap_or_default()
        .into_iter()
        .map(|(version, docs_url, class_hash)| {
            KnownAccountClass::new(
                AccountFamily::OpenZeppelin,
                class_hash,
                &version,
                &format!("OpenZeppelin AccountUpgradeable v{version}"),
                DEPLOYMENT_AND_IMPLEMENTATION,
                Some(ConstructorShape::PublicKey),
                &docs_url,
            )
        })
        .collect()
}

fn argent_cairo1_classes() -> Vec<KnownAccountClass> {
    ArgentAccount::known_classes()
        .into_iter()
        .map(|(class_hash, version, layout)| {
            KnownAccountClass::new(
                AccountFamily::Argent,
                class_hash,
                version.trim_start_matches('v'),
                &format!("Argent Account {version}"),
                DEPLOYMENT_AND_IMPLEMENTATION,
                Some(layout.into()),
                ARGENT_DEPLOYMENTS_SOURCE,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_class::ArgentConstructorLayout;
    use std::collections::HashSet;

    fn felt(hex: &str) -> Felt {
        Felt::from_hex(hex).unwrap()
    }

    #[test]
    fn every_class_hash_appears_once() {
        let classes = known_account_classes();
        let unique: HashSet<Felt> = classes.iter().map(|c| c.class_hash).collect();
        assert_eq!(
            unique.len(),
            classes.len(),
            "duplicate class hash in registry"
        );
    }

    #[test]
    fn every_entry_has_a_role_and_deployment_entries_have_a_constructor() {
        for class in known_account_classes() {
            assert!(!class.roles.is_empty(), "{} has no role", class.label);
            assert_eq!(
                class.constructor.is_some(),
                class.is_deployment_class(),
                "{}: constructor shape must be present exactly for deployment classes",
                class.label
            );
            assert!(!class.source.is_empty(), "{} has no source", class.label);
        }
    }

    #[test]
    fn braavos_entries_separate_deployment_from_implementation() {
        let base = lookup_account_class(&felt(BraavosAccount::BASE_CLASS_HASH_V100)).unwrap();
        assert_eq!(base.family, AccountFamily::Braavos);
        assert_eq!(base.roles, vec![ClassRole::Deployment]);
        assert_eq!(base.constructor, Some(ConstructorShape::PublicKey));

        let current = lookup_account_class(&felt(BraavosAccount::ACCOUNT_CLASS_HASH_V120)).unwrap();
        assert_eq!(current.roles, vec![ClassRole::Implementation]);
        assert_eq!(current.constructor, None);

        assert_eq!(deployment_classes(AccountFamily::Braavos).len(), 2);
        assert_eq!(implementation_classes(AccountFamily::Braavos).len(), 3);
    }

    #[test]
    fn argent_cairo1_entries_play_both_roles_with_their_layout() {
        let v040 = lookup_account_class(&felt(ArgentAccount::CLASS_HASH)).unwrap();
        assert_eq!(v040.family, AccountFamily::Argent);
        assert_eq!(v040.version, "0.4.0");
        assert_eq!(v040.roles, DEPLOYMENT_AND_IMPLEMENTATION);
        assert_eq!(
            v040.constructor.and_then(ConstructorShape::argent_layout),
            Some(ArgentConstructorLayout::SignerWithOptionalGuardian)
        );

        let v030 = lookup_account_class(&felt(ArgentAccount::CLASS_HASH_V030)).unwrap();
        assert_eq!(
            v030.constructor.and_then(ConstructorShape::argent_layout),
            Some(ArgentConstructorLayout::OwnerGuardianFelts)
        );
    }

    #[test]
    fn argent_cairo0_proxy_is_the_only_cairo0_deployment_class() {
        let proxy = lookup_account_class(&ArgentCairo0::proxy_class_hash()).unwrap();
        assert_eq!(proxy.roles, vec![ClassRole::Deployment]);
        assert_eq!(proxy.constructor, Some(ConstructorShape::ArgentCairo0Proxy));
        for (implementation, _) in ArgentCairo0::known_implementations() {
            let class = lookup_account_class(&implementation).unwrap();
            assert_eq!(class.roles, vec![ClassRole::Implementation]);
        }
    }

    #[test]
    fn openzeppelin_manifest_class_is_registered() {
        let oz: Vec<_> = known_account_classes()
            .into_iter()
            .filter(|c| c.family == AccountFamily::OpenZeppelin)
            .collect();
        assert!(!oz.is_empty(), "manifest classes must be in the registry");
        assert!(oz
            .iter()
            .all(|c| c.constructor == Some(ConstructorShape::PublicKey)));
    }

    #[test]
    fn unknown_class_hash_is_not_found() {
        assert_eq!(lookup_account_class(&Felt::from(0xabcdu64)), None);
    }

    #[test]
    fn json_uses_camel_case_fields_and_snake_case_values() {
        let base = lookup_account_class(&felt(BraavosAccount::CLASS_HASH)).unwrap();
        let json = serde_json::to_value(&base).unwrap();
        assert_eq!(json["family"], "braavos");
        assert_eq!(json["classHash"], format!("{:#x}", base.class_hash));
        assert_eq!(json["roles"], serde_json::json!(["deployment"]));
        assert_eq!(
            json["constructor"],
            serde_json::json!({
                "shape": "public_key",
                "fromSeed": "[public_key]",
                "withGuardian": null,
                "inputsOutsideSeed": [],
            })
        );
        assert!(json.get("class_hash").is_none());

        let v040 = lookup_account_class(&felt(ArgentAccount::CLASS_HASH)).unwrap();
        let json = serde_json::to_value(&v040).unwrap();
        assert_eq!(
            json["constructor"],
            serde_json::json!({
                "shape": "argent_signer_with_optional_guardian",
                "fromSeed": "[0, owner, 1]",
                "withGuardian": "[0, owner, 0, 0, guardian]",
                "inputsOutsideSeed": ["guardian"],
            })
        );
    }
}
