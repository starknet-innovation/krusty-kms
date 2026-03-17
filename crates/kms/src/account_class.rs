//! Account class trait and presets for Starknet account contracts.
//!
//! Provides a unified interface for computing deployment addresses across
//! different account contract implementations (OpenZeppelin, Argent, Braavos).

use crate::account::calculate_contract_address;
use krusty_kms_common::{ChainId, KmsError, Result};
use serde::Deserialize;
use starknet_types_core::felt::Felt;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const OZ_ACCOUNT_CLASS_MANIFEST_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/oz_account/class-hashes.json"
));

/// Policy for deriving the deployment salt from a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaltPolicy {
    /// Reuse the public key as the salt.
    PublicKey,
    /// Always deploy with zero salt.
    Zero,
    /// Use the provided salt value.
    Explicit(Felt),
}

impl SaltPolicy {
    /// Resolve the concrete salt for a given public key.
    pub fn resolve(self, public_key: &Felt) -> Felt {
        match self {
            SaltPolicy::PublicKey => *public_key,
            SaltPolicy::Zero => Felt::ZERO,
            SaltPolicy::Explicit(salt) => salt,
        }
    }
}

/// Trait representing a Starknet account contract class.
///
/// Each implementation knows its class hash and how to build
/// constructor calldata for a given public key.
pub trait AccountClass: Send + Sync {
    /// The class hash of the deployed contract.
    fn class_hash(&self) -> Felt;

    /// Build the constructor calldata for this account type.
    fn build_constructor_calldata(&self, public_key: &Felt) -> Vec<Felt>;

    /// Calculate the expected deployment address for a given public key.
    fn calculate_address(&self, public_key: &Felt, salt_policy: SaltPolicy) -> Result<Felt> {
        let salt = salt_policy.resolve(public_key);
        let calldata = self.build_constructor_calldata(public_key);
        calculate_contract_address(&salt, &self.class_hash(), &calldata, &Felt::ZERO)
    }
}

#[derive(Debug, Deserialize)]
struct OzAccountManifest {
    latest_version: String,
    package: String,
    contract_name: String,
    versions: BTreeMap<String, OzAccountManifestVersion>,
}

#[derive(Debug, Deserialize)]
struct OzAccountManifestVersion {
    source: OzAccountManifestSource,
    networks: BTreeMap<String, OzAccountManifestNetwork>,
}

#[derive(Debug, Deserialize)]
struct OzAccountManifestSource {
    docs: String,
    package: String,
}

#[derive(Debug, Deserialize)]
struct OzAccountManifestNetwork {
    declared_class_hash: String,
}

fn oz_account_manifest() -> Result<&'static OzAccountManifest> {
    static MANIFEST: OnceLock<std::result::Result<OzAccountManifest, String>> = OnceLock::new();

    match MANIFEST.get_or_init(|| {
        serde_json::from_str(OZ_ACCOUNT_CLASS_MANIFEST_JSON).map_err(|e| e.to_string())
    }) {
        Ok(manifest) => Ok(manifest),
        Err(msg) => Err(KmsError::DeserializationError(msg.clone())),
    }
}

/// Where an OpenZeppelin account class hash was resolved from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OzAccountClassSource {
    /// Loaded from the checked-in network manifest.
    Manifest {
        chain_id: ChainId,
        package_name: String,
        package_version: String,
        contract_name: String,
        docs_url: String,
        package_url: String,
    },
    /// Supplied explicitly by the caller.
    Custom,
}

/// Explicit configuration for an OpenZeppelin account class hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OzAccountClassConfig {
    class_hash: Felt,
    source: OzAccountClassSource,
}

impl OzAccountClassConfig {
    /// Resolve the latest manifest-backed class hash for a network.
    pub fn latest(chain_id: ChainId) -> Result<Self> {
        let manifest = oz_account_manifest()?;
        Self::from_manifest(chain_id, &manifest.latest_version)
    }

    /// Resolve a specific manifest-backed class hash for a network and version.
    pub fn from_manifest(chain_id: ChainId, version: &str) -> Result<Self> {
        let manifest = oz_account_manifest()?;
        let version_entry = manifest.versions.get(version).ok_or_else(|| {
            KmsError::InvalidClassHash(format!(
                "No OpenZeppelin account manifest entry for version {version}"
            ))
        })?;

        let network_entry = version_entry.networks.get(chain_id.name()).ok_or_else(|| {
            KmsError::InvalidClassHash(format!(
                "No OpenZeppelin account manifest entry for chain {} version {version}",
                chain_id.name()
            ))
        })?;

        let class_hash = Felt::from_hex(&network_entry.declared_class_hash)
            .map_err(|e| KmsError::InvalidClassHash(e.to_string()))?;

        Ok(Self {
            class_hash,
            source: OzAccountClassSource::Manifest {
                chain_id,
                package_name: manifest.package.clone(),
                package_version: version.to_string(),
                contract_name: manifest.contract_name.clone(),
                docs_url: version_entry.source.docs.clone(),
                package_url: version_entry.source.package.clone(),
            },
        })
    }

    /// Build a config from an explicit class hash.
    pub fn custom(class_hash: Felt) -> Self {
        Self {
            class_hash,
            source: OzAccountClassSource::Custom,
        }
    }

    /// The resolved class hash.
    pub fn class_hash(&self) -> Felt {
        self.class_hash
    }

    /// Metadata describing how the class hash was resolved.
    pub fn source(&self) -> &OzAccountClassSource {
        &self.source
    }
}

// ---------------------------------------------------------------------------
// OpenZeppelin Account
// ---------------------------------------------------------------------------

/// OpenZeppelin account contract preset.
///
/// Constructor: `(public_key)`
pub struct OpenZeppelinAccount {
    class_config: OzAccountClassConfig,
}

/// Bundles all deployment parameters for an OpenZeppelin account into one
/// inspectable value, ensuring the same canonical path is used for both
/// address derivation and the `DEPLOY_ACCOUNT` transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OzDeploymentDescriptor {
    pub address: Felt,
    pub class_hash: Felt,
    pub salt: Felt,
    pub constructor_calldata: Vec<Felt>,
    /// Always `Felt::ZERO` for counterfactual deployment.
    pub deployer_address: Felt,
}

impl OzDeploymentDescriptor {
    /// Return the address as a zero-padded hex string (`0x` + 64 hex chars).
    ///
    /// Prevents leading-zero ambiguity that can occur with `{:#x}` formatting.
    pub fn normalized_address_hex(&self) -> String {
        format!("0x{:064x}", self.address)
    }
}

impl OpenZeppelinAccount {
    /// Create from an explicit class hash configuration.
    pub fn new(class_config: OzAccountClassConfig) -> Self {
        Self { class_config }
    }

    /// Resolve the latest manifest-backed class hash for a network.
    pub fn latest(chain_id: ChainId) -> Result<Self> {
        Ok(Self::new(OzAccountClassConfig::latest(chain_id)?))
    }

    /// Resolve a specific manifest-backed class hash for a network and version.
    pub fn from_manifest(chain_id: ChainId, version: &str) -> Result<Self> {
        Ok(Self::new(OzAccountClassConfig::from_manifest(
            chain_id, version,
        )?))
    }

    /// Create from an explicit class hash.
    pub fn from_class_hash(class_hash: Felt) -> Self {
        Self::new(OzAccountClassConfig::custom(class_hash))
    }

    /// Inspect the resolved class configuration.
    pub fn class_config(&self) -> &OzAccountClassConfig {
        &self.class_config
    }

    /// Build an [`OzDeploymentDescriptor`] that captures every parameter
    /// needed for both address derivation and the deploy transaction.
    pub fn deployment_descriptor(
        &self,
        public_key: &Felt,
        salt_policy: SaltPolicy,
    ) -> Result<OzDeploymentDescriptor> {
        let salt = salt_policy.resolve(public_key);
        let constructor_calldata = self.build_constructor_calldata(public_key);
        let deployer_address = Felt::ZERO;
        let address = calculate_contract_address(
            &salt,
            &self.class_hash(),
            &constructor_calldata,
            &deployer_address,
        )?;

        Ok(OzDeploymentDescriptor {
            address,
            class_hash: self.class_hash(),
            salt,
            constructor_calldata,
            deployer_address,
        })
    }
}

impl AccountClass for OpenZeppelinAccount {
    fn class_hash(&self) -> Felt {
        self.class_config.class_hash()
    }

    fn build_constructor_calldata(&self, public_key: &Felt) -> Vec<Felt> {
        vec![*public_key]
    }
}

// ---------------------------------------------------------------------------
// Argent Account
// ---------------------------------------------------------------------------

/// Argent account contract preset.
///
/// Constructor: `(0, public_key, 0)` - CairoCustomEnum StarknetSigner variant + no guardian.
pub struct ArgentAccount {
    class_hash: Felt,
}

impl ArgentAccount {
    /// Argent Account class hash (Cairo 1, v0.4.0).
    pub const CLASS_HASH: &str =
        "0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f";

    pub fn new() -> Self {
        Self {
            class_hash: Felt::from_hex(Self::CLASS_HASH).unwrap(),
        }
    }

    /// Create with a custom class hash.
    pub fn with_class_hash(class_hash: Felt) -> Self {
        Self { class_hash }
    }
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
        vec![Felt::ZERO, *public_key, Felt::ZERO]
    }
}

// ---------------------------------------------------------------------------
// Braavos Account
// ---------------------------------------------------------------------------

/// Braavos account contract preset.
///
/// Constructor: `(public_key)`
pub struct BraavosAccount {
    class_hash: Felt,
}

impl BraavosAccount {
    /// Braavos Account class hash (Cairo 1).
    pub const CLASS_HASH: &str =
        "0x00816dd0297efc55dc1e7559020a3a825e81ef734b558f03c83325d4da7e6253";

    pub fn new() -> Self {
        Self {
            class_hash: Felt::from_hex(Self::CLASS_HASH).unwrap(),
        }
    }

    /// Create with a custom class hash.
    pub fn with_class_hash(class_hash: Felt) -> Self {
        Self { class_hash }
    }
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

    #[test]
    fn test_argent_calldata() {
        let argent = ArgentAccount::new();
        let pk = Felt::from(42u64);
        let cd = argent.build_constructor_calldata(&pk);
        assert_eq!(cd, vec![Felt::ZERO, pk, Felt::ZERO]);
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
}
