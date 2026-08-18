//! Unit tests for the account-class presets.

use super::*;

#[test]
fn test_oz_manifest_class_hash() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).unwrap();
    assert_ne!(oz.class_hash(), Felt::ZERO);
}

#[test]
fn test_oz_manifest_source_metadata() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).unwrap();
    let source = oz.class_config().source();
    match source {
        OzAccountClassSource::Manifest {
            chain_id,
            package_name,
            package_version,
            contract_name,
            ..
        } => {
            assert_eq!(*chain_id, ChainId::Sepolia);
            assert_eq!(package_name, "openzeppelin_presets");
            assert_eq!(package_version, "3.0.0");
            assert_eq!(contract_name, "AccountUpgradeable");
        }
        OzAccountClassSource::Custom => panic!("expected manifest-backed source"),
    }
}

#[test]
fn test_oz_calldata() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).unwrap();
    let pk = Felt::from(42u64);
    let cd = oz.build_constructor_calldata(&pk);
    assert_eq!(cd, vec![pk]);
}

/// v0.4.0 constructor is `(owner: Signer, guardian: Option<Signer>)`.
/// `Signer::Starknet` = variant 0, `Option::None` = variant 1.
#[test]
fn test_argent_v040_calldata() {
    let argent = ArgentAccount::new();
    let pk = Felt::from(42u64);
    let cd = argent.build_constructor_calldata(&pk);
    assert_eq!(
        cd,
        vec![Felt::ZERO, pk, Felt::ONE],
        "guardian must be Option::None (variant 1); variant 0 is Some and \
         makes the calldata a truncated Some, which fails to deserialize"
    );
}

/// v0.3.0 / v0.3.1 take a two-felt `(owner: felt252, guardian: felt252)`
/// constructor — not the Cairo enum encoding used from v0.4.0 on.
#[test]
fn test_argent_v03x_calldata() {
    let pk = Felt::from(42u64);
    for hash in [
        ArgentAccount::CLASS_HASH_V030,
        ArgentAccount::CLASS_HASH_V031,
    ] {
        let argent = ArgentAccount::with_class_hash(Felt::from_hex(hash).unwrap());
        assert_eq!(
            argent.build_constructor_calldata(&pk),
            vec![pk, Felt::ZERO],
            "v0.3.x constructor takes exactly two felts"
        );
    }
}

/// An unrecognised class hash must error, not return a guessed address.
///
/// `getAccountClassHashes()` publishes Argent Cairo-0 proxy hashes to JS
/// callers; those take a different constructor shape, so guessing the
/// v0.4.0 layout would hand back an undeployable address.
#[test]
fn test_argent_unknown_class_hash_is_rejected() {
    let pk = Felt::from(42u64);
    let cairo0_proxy =
        Felt::from_hex("0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918")
            .unwrap();

    for hash in [Felt::from(0xABCDEFu64), cairo0_proxy] {
        let argent = ArgentAccount::with_class_hash(hash);
        assert!(
            matches!(
                argent.calculate_address(&pk, SaltPolicy::PublicKey),
                Err(KmsError::InvalidClassHash(_))
            ),
            "unknown Argent class hash {hash:#x} must not derive an address"
        );
    }
}

/// Every known class hash must derive an address (no accidental rejections).
#[test]
fn test_argent_known_class_hashes_all_derive() {
    let pk = Felt::from(42u64);
    for hash in ArgentAccount::known_class_hashes() {
        assert!(ArgentAccount::with_class_hash(hash)
            .calculate_address(&pk, SaltPolicy::PublicKey)
            .is_ok());
    }
}

#[test]
fn test_braavos_calldata() {
    let braavos = BraavosAccount::new();
    let pk = Felt::from(42u64);
    let cd = braavos.build_constructor_calldata(&pk);
    assert_eq!(cd, vec![pk]);
}

#[test]
fn test_address_deterministic() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).unwrap();
    let pk = Felt::from(12345u64);
    let addr1 = oz.calculate_address(&pk, SaltPolicy::PublicKey).unwrap();
    let addr2 = oz.calculate_address(&pk, SaltPolicy::PublicKey).unwrap();
    assert_eq!(addr1, addr2);
}

#[test]
fn test_different_classes_different_addresses() {
    let pk = Felt::from(12345u64);
    let oz_addr = OpenZeppelinAccount::latest(ChainId::Sepolia)
        .unwrap()
        .calculate_address(&pk, SaltPolicy::PublicKey)
        .unwrap();
    let argent_addr = ArgentAccount::new()
        .calculate_address(&pk, SaltPolicy::PublicKey)
        .unwrap();
    let braavos_addr = BraavosAccount::new()
        .calculate_address(&pk, SaltPolicy::PublicKey)
        .unwrap();

    assert_ne!(oz_addr, argent_addr);
    assert_ne!(oz_addr, braavos_addr);
    assert_ne!(argent_addr, braavos_addr);
}

#[test]
fn test_public_key_salt_policy() {
    let pk = Felt::from(999u64);
    assert_eq!(SaltPolicy::PublicKey.resolve(&pk), pk);
}

#[test]
fn test_zero_salt_policy() {
    let pk = Felt::from(999u64);
    assert_eq!(SaltPolicy::Zero.resolve(&pk), Felt::ZERO);
}

#[test]
fn test_explicit_salt_policy() {
    let pk = Felt::from(999u64);
    let salt = Felt::from(777u64);
    assert_eq!(SaltPolicy::Explicit(salt).resolve(&pk), salt);
}

#[test]
fn test_custom_class_hash() {
    let custom_hash = Felt::from(0xDEADBEEFu64);
    let oz = OpenZeppelinAccount::from_class_hash(custom_hash);
    assert_eq!(oz.class_hash(), custom_hash);
    assert!(matches!(
        oz.class_config().source(),
        OzAccountClassSource::Custom
    ));
}

// -----------------------------------------------------------------------
// OzDeploymentDescriptor consistency tests
// -----------------------------------------------------------------------

#[test]
fn test_descriptor_address_matches_calculate_address() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).unwrap();
    let pk = Felt::from(12345u64);
    let descriptor = oz
        .deployment_descriptor(&pk, SaltPolicy::PublicKey)
        .unwrap();
    let addr = oz.calculate_address(&pk, SaltPolicy::PublicKey).unwrap();
    assert_eq!(descriptor.address, addr);
}

#[test]
fn test_descriptor_public_key_salt() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).unwrap();
    let pk = Felt::from(42u64);
    let descriptor = oz
        .deployment_descriptor(&pk, SaltPolicy::PublicKey)
        .unwrap();
    assert_eq!(descriptor.salt, pk);
}

#[test]
fn test_descriptor_zero_salt() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).unwrap();
    let pk = Felt::from(42u64);
    let descriptor = oz.deployment_descriptor(&pk, SaltPolicy::Zero).unwrap();
    assert_eq!(descriptor.salt, Felt::ZERO);
}

#[test]
fn test_descriptor_deployer_is_zero() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).unwrap();
    let pk = Felt::from(42u64);
    let descriptor = oz
        .deployment_descriptor(&pk, SaltPolicy::PublicKey)
        .unwrap();
    assert_eq!(descriptor.deployer_address, Felt::ZERO);
}

#[test]
fn test_descriptor_calldata_is_pubkey() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).unwrap();
    let pk = Felt::from(42u64);
    let descriptor = oz
        .deployment_descriptor(&pk, SaltPolicy::PublicKey)
        .unwrap();
    assert_eq!(descriptor.constructor_calldata, vec![pk]);
}

#[test]
fn test_normalized_hex_has_leading_zeros() {
    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).unwrap();
    let pk = Felt::from(1u64);
    let descriptor = oz
        .deployment_descriptor(&pk, SaltPolicy::PublicKey)
        .unwrap();
    let hex = descriptor.normalized_address_hex();
    assert_eq!(
        hex.len(),
        66,
        "expected 66 chars, got {}: {}",
        hex.len(),
        hex
    );
    assert!(hex.starts_with("0x"));
}

#[test]
fn test_custom_class_hash_descriptor() {
    let custom_hash = Felt::from(0xDEADBEEFu64);
    let oz = OpenZeppelinAccount::from_class_hash(custom_hash);
    let pk = Felt::from(99u64);
    let descriptor = oz
        .deployment_descriptor(&pk, SaltPolicy::PublicKey)
        .unwrap();
    assert_eq!(descriptor.class_hash, custom_hash);
    assert_eq!(
        descriptor.address,
        oz.calculate_address(&pk, SaltPolicy::PublicKey).unwrap()
    );
}
