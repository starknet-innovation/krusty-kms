//! Registry of known Starknet account classes, labelled by the role each
//! class plays.
//!
//! A class hash plays one of two roles for an account, and callers need to
//! tell them apart:
//!
//! - a **deployment** class fixes the contract address. It is the
//!   `class_hash` of the `DEPLOY_ACCOUNT` transaction and the only class an
//!   address can be derived from;
//! - an **implementation** role marks a class an account's address can report
//!   on chain (`starknet_getClassHashAt`) and that a signer must accept. A class
//!   may also have the deployment role and fix addresses; an implementation-only
//!   class cannot be used for derivation. A third role, **proxy target**, is the
//!   class a proxy delegates to: code the account runs that no address reports.
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
/// Proxy target only: the class runs behind a proxy and is never an account's
/// own class hash on chain.
pub(crate) const PROXY_TARGET_ONLY: &[ClassRole] = &[ClassRole::ProxyTarget];

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
    /// The class an account's address reports on chain
    /// (`starknet_getClassHashAt`). Accept it when signing.
    Implementation,
    /// The class a proxy delegates to, named in the proxy's constructor
    /// calldata. It is code the account runs, but it is never the account's
    /// own class hash, so an allowlist built for signing must not expect it:
    /// an Argent Cairo 0 account reports its *proxy* class.
    ProxyTarget,
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

    /// Whether an account's address reports this class on chain (accept it
    /// when signing). False for a proxy target, which no address reports.
    pub fn is_implementation_class(&self) -> bool {
        self.roles.contains(&ClassRole::Implementation)
    }

    /// Whether this class runs behind a proxy rather than as an account's own
    /// class. These are the values the proxy's `implementation` constructor
    /// input takes.
    pub fn is_proxy_target(&self) -> bool {
        self.roles.contains(&ClassRole::ProxyTarget)
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

/// Classes an account of `family` can report on chain: accept these when
/// signing. Excludes proxy targets, which no address reports; see
/// [`proxy_target_classes`].
pub fn implementation_classes(family: AccountFamily) -> Vec<KnownAccountClass> {
    known_account_classes()
        .into_iter()
        .filter(|class| class.family == family && class.is_implementation_class())
        .collect()
}

/// Classes of `family` that run behind a proxy: the values the proxy's
/// `implementation` constructor input takes.
pub fn proxy_target_classes(family: AccountFamily) -> Vec<KnownAccountClass> {
    known_account_classes()
        .into_iter()
        .filter(|class| class.family == family && class.is_proxy_target())
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
mod tests;
