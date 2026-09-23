//! `inspect_deployment`: derivability verdicts for concrete deployments.

use crate::vectors::{
    foreign_salt, inspection_guardian_key, inspection_owner_key, server_assigned_salt, zero_salt,
};
use krusty_kms::{
    inspect_deployment, AccountClass, ArgentAccount, ArgentCairo0, BraavosAccount, Derivability,
    NotDerivableReason, OpenZeppelinAccount,
};
use krusty_kms_common::ChainId;
use starknet_types_core::felt::Felt;

fn felt(hex: &str) -> Felt {
    Felt::from_hex(hex).unwrap()
}

fn pk() -> Felt {
    inspection_owner_key()
}

#[test]
fn braavos_base_deployment_is_from_seed() {
    for hash in BraavosAccount::deployment_class_hashes() {
        let inspection = inspect_deployment(&hash, &pk(), &[pk()]);
        assert_eq!(inspection.derivability, Derivability::FromSeed, "{hash:#x}");
        assert_eq!(inspection.owner_public_key, Some(pk()));
        assert_eq!(inspection.class.unwrap().class_hash, hash);
    }
}

#[test]
fn braavos_implementation_class_is_never_a_deployment() {
    for hash in BraavosAccount::implementation_class_hashes() {
        let inspection = inspect_deployment(&hash, &pk(), &[pk()]);
        assert_eq!(
            inspection.derivability,
            Derivability::NotFromSeed(NotDerivableReason::ImplementationClass),
            "{hash:#x}"
        );
        assert!(inspection.class.is_some(), "class is still recognised");
    }
}

#[test]
fn braavos_salt_other_than_public_key_is_not_from_seed() {
    let base = felt(BraavosAccount::CLASS_HASH);
    let inspection = inspect_deployment(&base, &foreign_salt(), &[pk()]);
    assert_eq!(
        inspection.derivability,
        Derivability::NotFromSeed(NotDerivableReason::SaltNotPublicKey)
    );
    assert_eq!(inspection.owner_public_key, Some(pk()));
    let malformed = inspect_deployment(&base, &pk(), &[pk(), Felt::ZERO]);
    assert_eq!(
        malformed.derivability,
        Derivability::NotFromSeed(NotDerivableReason::UnexpectedConstructorCalldata)
    );
}

#[test]
fn openzeppelin_accepts_public_key_or_zero_salt() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia)
        .unwrap()
        .class_hash();
    assert_eq!(
        inspect_deployment(&oz, &pk(), &[pk()]).derivability,
        Derivability::FromSeed
    );
    assert_eq!(
        inspect_deployment(&oz, &zero_salt(), &[pk()]).derivability,
        Derivability::FromSeed
    );
    assert_eq!(
        inspect_deployment(&oz, &foreign_salt(), &[pk()]).derivability,
        Derivability::NotFromSeed(NotDerivableReason::SaltNotPublicKey)
    );
}

#[test]
fn argent_v040_guardian_and_owner_kind_decide_derivability() {
    let v040 = felt(ArgentAccount::CLASS_HASH);
    let guardian = inspection_guardian_key();

    let plain = inspect_deployment(&v040, &pk(), &[Felt::ZERO, pk(), Felt::ONE]);
    assert_eq!(plain.derivability, Derivability::FromSeed);
    assert_eq!(plain.owner_public_key, Some(pk()));

    // Option::Some(Signer::Starknet(guardian)) is tag 0, variant 0, pubkey.
    let guarded = inspect_deployment(
        &v040,
        &pk(),
        &[Felt::ZERO, pk(), Felt::ZERO, Felt::ZERO, guardian],
    );
    assert_eq!(
        guarded.derivability,
        Derivability::NotFromSeed(NotDerivableReason::Guardian)
    );
    assert_eq!(
        guarded.owner_public_key,
        Some(pk()),
        "owner is still reported"
    );
    assert_eq!(guarded.guardian_public_key, Some(guardian));

    // Signer::Eip191 owner (variant 3): not a Stark key at all.
    let eip191 = inspect_deployment(&v040, &pk(), &[Felt::THREE, Felt::from(0xeeu64), Felt::ONE]);
    assert_eq!(
        eip191.derivability,
        Derivability::NotFromSeed(NotDerivableReason::NonStarknetOwner)
    );

    // Server-assigned salt (Argent smart account).
    let salted = inspect_deployment(
        &v040,
        &server_assigned_salt(),
        &[Felt::ZERO, pk(), Felt::ONE],
    );
    assert_eq!(
        salted.derivability,
        Derivability::NotFromSeed(NotDerivableReason::SaltNotPublicKey)
    );

    // The historical `[0, pk, 0]` shape is a Some tag with no payload.
    let broken = inspect_deployment(&v040, &pk(), &[Felt::ZERO, pk(), Felt::ZERO]);
    assert_eq!(
        broken.derivability,
        Derivability::NotFromSeed(NotDerivableReason::UnexpectedConstructorCalldata)
    );
}

#[test]
fn argent_v03_guardian_felt_decides_derivability() {
    let v031 = felt(ArgentAccount::CLASS_HASH_V031);
    assert_eq!(
        inspect_deployment(&v031, &pk(), &[pk(), Felt::ZERO]).derivability,
        Derivability::FromSeed
    );
    let guarded = inspect_deployment(&v031, &pk(), &[pk(), Felt::from(5u64)]);
    assert_eq!(
        guarded.derivability,
        Derivability::NotFromSeed(NotDerivableReason::Guardian)
    );
    assert_eq!(guarded.owner_public_key, Some(pk()));
    assert_eq!(guarded.guardian_public_key, Some(Felt::from(5u64)));
}

#[test]
fn argent_cairo0_proxy_follows_implementation_and_guardian() {
    let proxy = ArgentCairo0::proxy_class_hash();
    let (implementation, _) = ArgentCairo0::known_implementations()[0];
    let calldata = ArgentCairo0::constructor_calldata(&implementation, &pk());
    let inspection = inspect_deployment(&proxy, &pk(), &calldata);
    assert_eq!(inspection.derivability, Derivability::FromSeed);
    assert_eq!(inspection.owner_public_key, Some(pk()));

    let guarded =
        ArgentCairo0::constructor_calldata_with_guardian(&implementation, &pk(), &Felt::from(9u64));
    let guarded = inspect_deployment(&proxy, &pk(), &guarded);
    assert_eq!(
        guarded.derivability,
        Derivability::NotFromSeed(NotDerivableReason::Guardian)
    );
    assert_eq!(guarded.guardian_public_key, Some(Felt::from(9u64)));

    // The proxy is known; the class it delegates to is not, so discovery
    // would not find this account even though its address is a function of
    // the owner key. That is its own reason, not "unknown class".
    let unknown_impl = ArgentCairo0::constructor_calldata(&Felt::from(0xabcdu64), &pk());
    let unknown = inspect_deployment(&proxy, &pk(), &unknown_impl);
    assert_eq!(
        unknown.derivability,
        Derivability::NotFromSeed(NotDerivableReason::UnknownProxyImplementation)
    );
    assert!(unknown.class.is_some(), "the proxy itself is recognised");
    assert_eq!(unknown.owner_public_key, Some(pk()));

    assert_eq!(
        inspect_deployment(&proxy, &pk(), &[pk()]).derivability,
        Derivability::NotFromSeed(NotDerivableReason::UnexpectedConstructorCalldata)
    );
}

#[test]
fn unknown_class_hash_yields_no_verdict() {
    let inspection = inspect_deployment(&Felt::from(0xabcdu64), &pk(), &[pk()]);
    assert_eq!(inspection.derivability, Derivability::UnknownClass);
    assert_eq!(inspection.class, None);
    assert_eq!(inspection.owner_public_key, None);
}

/// A class that only runs behind a proxy is not an implementation class: no
/// account reports it, and nothing is deployed with it. The verdict says so
/// rather than calling it the class an upgraded account runs.
#[test]
fn argent_cairo0_target_is_reported_as_a_proxy_target() {
    for (implementation, version) in ArgentCairo0::known_implementations() {
        let inspection = inspect_deployment(&implementation, &pk(), &[pk()]);
        assert_eq!(
            inspection.derivability,
            Derivability::NotFromSeed(NotDerivableReason::ProxyTargetClass),
            "Argent Cairo 0 v{version}"
        );
        let class = inspection.class.expect("the target is a known class");
        assert!(class.is_proxy_target());
        assert!(!class.is_implementation_class());
    }

    // A class an upgraded account really does report keeps the other reason.
    let braavos_implementation = BraavosAccount::implementation_class_hashes()[0];
    assert_eq!(
        inspect_deployment(&braavos_implementation, &pk(), &[pk()]).derivability,
        Derivability::NotFromSeed(NotDerivableReason::ImplementationClass)
    );
}

/// A zero owner is not a public key any seed derives: `stark_public_key`
/// cannot produce one. Such a deployment is malformed, not discoverable, even
/// where the salt matches trivially because both are zero.
#[test]
fn zero_owner_is_malformed_not_from_seed() {
    let braavos = felt(BraavosAccount::CLASS_HASH);
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia)
        .unwrap()
        .class_hash();
    let proxy = ArgentCairo0::proxy_class_hash();
    let (implementation, _) = ArgentCairo0::known_implementations()[0];

    let malformed = Derivability::NotFromSeed(NotDerivableReason::UnexpectedConstructorCalldata);
    for (class_hash, salt, calldata) in [
        // salt == owner == 0 would otherwise look like the Braavos shape.
        (braavos, zero_salt(), vec![Felt::ZERO]),
        // The OpenZeppelin legacy variant deploys with a zero salt.
        (oz, zero_salt(), vec![Felt::ZERO]),
        (oz, Felt::ZERO, vec![Felt::ZERO]),
        (
            proxy,
            Felt::ZERO,
            ArgentCairo0::constructor_calldata(&implementation, &Felt::ZERO),
        ),
    ] {
        let inspection = inspect_deployment(&class_hash, &salt, &calldata);
        assert_eq!(inspection.derivability, malformed, "{class_hash:#x}");
        assert_eq!(inspection.owner_public_key, None);
    }
}
