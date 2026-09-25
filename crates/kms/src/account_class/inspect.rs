//! Derivability of a concrete account deployment.
//!
//! Two operations are easy to conflate:
//!
//! - **Discovery** (phrase to addresses): [`crate::generate_candidates`]
//!   enumerates the addresses a seed reproduces on its own. An Argent account
//!   with a guardian is not among them: the guardian is per-account, part of
//!   the constructor calldata and so of the address, and not derived from the
//!   seed.
//! - **Verification** (phrase plus a known address: is this mine?): possible
//!   for those same accounts. The guardian in the account's `DEPLOY_ACCOUNT`
//!   calldata reproduces the address exactly. It must come from that
//!   transaction: an account's current guardian can have been changed or
//!   removed since, and a changed one no longer reproduces the address.
//!
//! A recovery flow that cannot tell "not discoverable from a phrase" apart
//! from "no such account" tells users their funds are gone.
//! [`inspect_deployment`] takes the three `DEPLOY_ACCOUNT` fields that fix an
//! address and states which case applies. It returns the address those fields
//! fix and the owner and guardian keys they name; a caller verifies an
//! account by checking both the address and the owner key.

use super::argent_cairo0::ArgentCairo0;
use super::registry::{lookup_account_class, AccountFamily, ConstructorShape, KnownAccountClass};
use super::DecodedArgentConstructor;
use crate::account::calculate_contract_address;
use crate::stark_signing::is_stark_public_key;
use starknet_types_core::felt::Felt;

/// Why an account's address is not a function of a seed-derived key alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotDerivableReason {
    /// The constructor binds a guardian. It is per-account and not derived
    /// from the seed, so discovery cannot enumerate the address; given the
    /// deploy calldata's guardian (not the account's current one, which can
    /// have changed), [`crate::ArgentAccount::calculate_address_with_guardian`]
    /// reproduces it.
    Guardian,
    /// The owner is not a Starknet-curve signer (Argent v0.4.0+ Secp256k1,
    /// Secp256r1, EIP-191 or WebAuthn owner).
    NonStarknetOwner,
    /// The salt is not the owner public key (nor zero, for OpenZeppelin).
    /// Argent smart accounts are assigned their salt server-side.
    SaltNotPublicKey,
    /// The class is an implementation class: it is what an upgraded account
    /// runs, never what fixed its address. Inspect the `DEPLOY_ACCOUNT`
    /// class hash instead of the current one.
    ImplementationClass,
    /// The class runs behind a proxy and is never an account's own class
    /// hash, so nothing is deployed with it. For an Argent Cairo 0 account,
    /// inspect the proxy class with the proxy's constructor calldata; this
    /// class is the `implementation` argument inside that calldata.
    ProxyTargetClass,
    /// An Argent Cairo 0 proxy pointing at an implementation this crate does
    /// not know. The address is a function of the seed key in principle, but
    /// discovery only tries the known implementations, so it will not find
    /// this account.
    UnknownProxyImplementation,
    /// The constructor calldata does not match the class's known layout.
    UnexpectedConstructorCalldata,
}

/// Whether a deployment can be found by deriving addresses from a seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Derivability {
    /// The address is a function of the owner's Stark public key alone, so
    /// [`crate::generate_candidates`] reproduces it from the seed.
    FromSeed,
    /// The account exists but its address depends on inputs outside the seed.
    /// Discovery cannot enumerate it; verification against a known address
    /// may still succeed (see [`DeploymentInspection::owner_public_key`]).
    NotFromSeed(NotDerivableReason),
    /// The deployment class hash is not in the registry, so nothing can be
    /// said. [`DeploymentInspection::class`] is `None` in this case.
    UnknownClass,
}

/// The result of [`inspect_deployment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentInspection {
    /// The address the inspected fields fix (deployer zero). Compare it with
    /// the account being checked: fields that do not hash to that address say
    /// nothing about it, whatever keys they name.
    pub address: Felt,
    /// The registry entry for the deployment class, if recognised.
    pub class: Option<KnownAccountClass>,
    /// The Stark public key the constructor binds as owner, when it has one.
    /// A match with one of the seed's derived keys shows these fields name
    /// the seed's key; together with a matching [`Self::address`] it shows
    /// the account is the seed's, even when discovery cannot find it.
    pub owner_public_key: Option<Felt>,
    /// The guardian's Stark public key, when the constructor binds a
    /// Starknet-key guardian.
    pub guardian_public_key: Option<Felt>,
    pub derivability: Derivability,
}

impl DeploymentInspection {
    fn unknown_class(class: Option<KnownAccountClass>) -> Self {
        Self {
            address: Felt::ZERO,
            class,
            owner_public_key: None,
            guardian_public_key: None,
            derivability: Derivability::UnknownClass,
        }
    }

    fn not_from_seed(
        class: KnownAccountClass,
        owner: Option<Felt>,
        reason: NotDerivableReason,
    ) -> Self {
        Self {
            address: Felt::ZERO,
            class: Some(class),
            owner_public_key: owner,
            guardian_public_key: None,
            derivability: Derivability::NotFromSeed(reason),
        }
    }

    fn guarded(class: KnownAccountClass, owner: Felt, guardian: Option<Felt>) -> Self {
        Self {
            address: Felt::ZERO,
            class: Some(class),
            owner_public_key: Some(owner),
            guardian_public_key: guardian,
            derivability: Derivability::NotFromSeed(NotDerivableReason::Guardian),
        }
    }

    fn from_seed(class: KnownAccountClass, owner: Felt) -> Self {
        Self {
            address: Felt::ZERO,
            class: Some(class),
            owner_public_key: Some(owner),
            guardian_public_key: None,
            derivability: Derivability::FromSeed,
        }
    }
}

/// State whether a deployment's address is a function of a seed-derived key.
///
/// The arguments are the `DEPLOY_ACCOUNT` transaction's `class_hash`,
/// `contract_address_salt` and `constructor_calldata`: the three inputs that
/// fix a counterfactual address. Passing an implementation-only class yields
/// [`NotDerivableReason::ImplementationClass`]. A current class that also has
/// the deployment role is inspected as a possible deployment class, so use the
/// deploy transaction's class hash and always compare
/// [`DeploymentInspection::address`].
///
/// The fields are untrusted input (typically an RPC response): the verdict is
/// about these fields, and [`DeploymentInspection::address`] is what binds
/// them to an account.
pub fn inspect_deployment(
    class_hash: &Felt,
    salt: &Felt,
    constructor_calldata: &[Felt],
) -> DeploymentInspection {
    let mut inspection = classify(class_hash, salt, constructor_calldata);
    inspection.address =
        calculate_contract_address(salt, class_hash, constructor_calldata, &Felt::ZERO)
            .expect("the contract address prefix is a valid short string");
    inspection
}

fn classify(class_hash: &Felt, salt: &Felt, constructor_calldata: &[Felt]) -> DeploymentInspection {
    let Some(class) = lookup_account_class(class_hash) else {
        return DeploymentInspection::unknown_class(None);
    };
    let Some(shape) = class.constructor else {
        // Every deployment class has a shape. A class without one is either
        // what an upgraded account reports, or a class that only ever runs
        // behind a proxy; the registry's roles tell them apart.
        let reason = if class.is_proxy_target() {
            NotDerivableReason::ProxyTargetClass
        } else {
            NotDerivableReason::ImplementationClass
        };
        return DeploymentInspection::not_from_seed(class, None, reason);
    };
    match shape {
        ConstructorShape::PublicKey => {
            inspect_public_key_constructor(class, salt, constructor_calldata)
        }
        ConstructorShape::ArgentOwnerGuardianFelts
        | ConstructorShape::ArgentSignerWithOptionalGuardian => {
            inspect_argent_constructor(class, shape, salt, constructor_calldata)
        }
        ConstructorShape::ArgentCairo0Proxy => {
            inspect_argent_cairo0_proxy(class, salt, constructor_calldata)
        }
    }
}

/// `[public_key]`: OpenZeppelin and the Braavos base account. Braavos wallets
/// salt with the public key; OpenZeppelin deployments use either the public
/// key or zero, and discovery covers both.
fn inspect_public_key_constructor(
    class: KnownAccountClass,
    salt: &Felt,
    calldata: &[Felt],
) -> DeploymentInspection {
    let [owner] = calldata else {
        return DeploymentInspection::not_from_seed(
            class,
            None,
            NotDerivableReason::UnexpectedConstructorCalldata,
        );
    };
    if !is_stark_public_key(owner) {
        // Not an x-coordinate of any curve point, so no key derived from a
        // seed equals it, whatever the salt. Zero is one such felt.
        return DeploymentInspection::not_from_seed(
            class,
            None,
            NotDerivableReason::UnexpectedConstructorCalldata,
        );
    }
    let zero_salt_allowed = class.family == AccountFamily::OpenZeppelin && *salt == Felt::ZERO;
    if *salt == *owner || zero_salt_allowed {
        DeploymentInspection::from_seed(class, *owner)
    } else {
        DeploymentInspection::not_from_seed(
            class,
            Some(*owner),
            NotDerivableReason::SaltNotPublicKey,
        )
    }
}

fn inspect_argent_constructor(
    class: KnownAccountClass,
    shape: ConstructorShape,
    salt: &Felt,
    calldata: &[Felt],
) -> DeploymentInspection {
    let layout = shape
        .argent_layout()
        .expect("Argent shapes map to a layout");
    match layout.decode(calldata) {
        Err(_) => DeploymentInspection::not_from_seed(
            class,
            None,
            NotDerivableReason::UnexpectedConstructorCalldata,
        ),
        Ok(DecodedArgentConstructor::NonStarknetOwner { .. }) => {
            DeploymentInspection::not_from_seed(class, None, NotDerivableReason::NonStarknetOwner)
        }
        Ok(DecodedArgentConstructor::StarknetOwnerWithGuardian { owner, guardian }) => {
            malformed_owner(&class, &owner)
                .unwrap_or_else(|| DeploymentInspection::guarded(class, owner, guardian))
        }
        Ok(DecodedArgentConstructor::StarknetOwnerNoGuardian { owner }) => {
            malformed_owner(&class, &owner)
                .unwrap_or_else(|| owner_salt_verdict(class, owner, salt))
        }
    }
}

/// `[implementation, selector("initialize"), 2, owner, guardian]`.
fn inspect_argent_cairo0_proxy(
    class: KnownAccountClass,
    salt: &Felt,
    calldata: &[Felt],
) -> DeploymentInspection {
    let [implementation, selector, arity, owner, guardian] = calldata else {
        return DeploymentInspection::not_from_seed(
            class,
            None,
            NotDerivableReason::UnexpectedConstructorCalldata,
        );
    };
    if *selector != ArgentCairo0::initialize_selector() || *arity != Felt::TWO {
        return DeploymentInspection::not_from_seed(
            class,
            None,
            NotDerivableReason::UnexpectedConstructorCalldata,
        );
    }
    if let Some(inspection) = malformed_owner(&class, owner) {
        return inspection;
    }
    if !ArgentCairo0::is_known_implementation(implementation) {
        // The proxy class *is* known; its target is not. Discovery only tries
        // the known implementations, so it would not find this account.
        return DeploymentInspection::not_from_seed(
            class,
            Some(*owner),
            NotDerivableReason::UnknownProxyImplementation,
        );
    }
    if *guardian != Felt::ZERO {
        return DeploymentInspection::guarded(class, *owner, Some(*guardian));
    }
    owner_salt_verdict(class, *owner, salt)
}

/// The verdict for an owner that is not a public key, if it is not one.
///
/// Every path that reports an owner runs this first, so no verdict names a
/// felt that no seed-derived key can equal.
fn malformed_owner(class: &KnownAccountClass, owner: &Felt) -> Option<DeploymentInspection> {
    (!is_stark_public_key(owner)).then(|| {
        DeploymentInspection::not_from_seed(
            class.clone(),
            None,
            NotDerivableReason::UnexpectedConstructorCalldata,
        )
    })
}

fn owner_salt_verdict(class: KnownAccountClass, owner: Felt, salt: &Felt) -> DeploymentInspection {
    if *salt == owner {
        DeploymentInspection::from_seed(class, owner)
    } else {
        DeploymentInspection::not_from_seed(
            class,
            Some(owner),
            NotDerivableReason::SaltNotPublicKey,
        )
    }
}
