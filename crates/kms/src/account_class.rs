//! Account class trait and presets for Starknet account contracts.
//!
//! Provides a unified interface for computing deployment addresses across
//! different account contract implementations (OpenZeppelin, Argent, Braavos).

use crate::account::calculate_contract_address;
use krusty_kms_common::Result;
use starknet_types_core::felt::Felt;

/// Trait representing a Starknet account contract class.
///
/// Each implementation knows its class hash and how to build
/// constructor calldata for a given public key.
pub trait AccountClass: Send + Sync {
    /// The class hash of the deployed contract.
    fn class_hash(&self) -> Felt;

    /// Build the constructor calldata for this account type.
    fn build_constructor_calldata(&self, public_key: &Felt) -> Vec<Felt>;

    /// Compute the salt used for address derivation. Defaults to the public key.
    fn get_salt(&self, public_key: &Felt) -> Felt {
        *public_key
    }

    /// Calculate the expected deployment address for a given public key.
    fn calculate_address(&self, public_key: &Felt) -> Result<Felt> {
        let salt = self.get_salt(public_key);
        let calldata = self.build_constructor_calldata(public_key);
        calculate_contract_address(&salt, &self.class_hash(), &calldata, &Felt::ZERO)
    }
}

// ---------------------------------------------------------------------------
// OpenZeppelin Account
// ---------------------------------------------------------------------------

/// OpenZeppelin account contract preset.
///
/// Constructor: `(public_key)`
pub struct OpenZeppelinAccount {
    class_hash: Felt,
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
    /// OpenZeppelin Account class hash (Cairo 1, v0.14.0).
    pub const CLASS_HASH: &str =
        "0x061dac032f228abef9c6f3bc0dfc5972e1e5e3fa30b32ab204e73e0fea77730d";

    pub fn new() -> Self {
        Self {
            class_hash: Felt::from_hex(Self::CLASS_HASH).unwrap(),
        }
    }

    /// Create with a custom class hash.
    pub fn with_class_hash(class_hash: Felt) -> Self {
        Self { class_hash }
    }

    /// Build an [`OzDeploymentDescriptor`] that captures every parameter
    /// needed for both address derivation and the deploy transaction.
    pub fn deployment_descriptor(&self, public_key: &Felt) -> Result<OzDeploymentDescriptor> {
        let salt = self.get_salt(public_key);
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

impl Default for OpenZeppelinAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountClass for OpenZeppelinAccount {
    fn class_hash(&self) -> Felt {
        self.class_hash
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
/// Constructor: `(0, public_key, 0)` — CairoCustomEnum StarknetSigner variant + no guardian.
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
        // CairoCustomEnum: variant 0 = StarknetSigner, then pubkey, then guardian = 0
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
    fn test_oz_class_hash() {
        let oz = OpenZeppelinAccount::new();
        assert_ne!(oz.class_hash(), Felt::ZERO);
    }

    #[test]
    fn test_oz_calldata() {
        let oz = OpenZeppelinAccount::new();
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
        let oz = OpenZeppelinAccount::new();
        let pk = Felt::from(12345u64);
        let addr1 = oz.calculate_address(&pk).unwrap();
        let addr2 = oz.calculate_address(&pk).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_different_classes_different_addresses() {
        let pk = Felt::from(12345u64);
        let oz_addr = OpenZeppelinAccount::new().calculate_address(&pk).unwrap();
        let argent_addr = ArgentAccount::new().calculate_address(&pk).unwrap();
        let braavos_addr = BraavosAccount::new().calculate_address(&pk).unwrap();

        assert_ne!(oz_addr, argent_addr);
        assert_ne!(oz_addr, braavos_addr);
        assert_ne!(argent_addr, braavos_addr);
    }

    #[test]
    fn test_default_salt_is_pubkey() {
        let oz = OpenZeppelinAccount::new();
        let pk = Felt::from(999u64);
        assert_eq!(oz.get_salt(&pk), pk);
    }

    #[test]
    fn test_custom_class_hash() {
        let custom_hash = Felt::from(0xDEADBEEFu64);
        let oz = OpenZeppelinAccount::with_class_hash(custom_hash);
        assert_eq!(oz.class_hash(), custom_hash);
    }

    // -----------------------------------------------------------------------
    // OzDeploymentDescriptor consistency tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_descriptor_address_matches_calculate_address() {
        let oz = OpenZeppelinAccount::new();
        let pk = Felt::from(12345u64);
        let descriptor = oz.deployment_descriptor(&pk).unwrap();
        let addr = oz.calculate_address(&pk).unwrap();
        assert_eq!(descriptor.address, addr);
    }

    #[test]
    fn test_descriptor_salt_is_public_key() {
        let oz = OpenZeppelinAccount::new();
        let pk = Felt::from(42u64);
        let descriptor = oz.deployment_descriptor(&pk).unwrap();
        assert_eq!(descriptor.salt, pk);
    }

    #[test]
    fn test_descriptor_deployer_is_zero() {
        let oz = OpenZeppelinAccount::new();
        let pk = Felt::from(42u64);
        let descriptor = oz.deployment_descriptor(&pk).unwrap();
        assert_eq!(descriptor.deployer_address, Felt::ZERO);
    }

    #[test]
    fn test_descriptor_calldata_is_pubkey() {
        let oz = OpenZeppelinAccount::new();
        let pk = Felt::from(42u64);
        let descriptor = oz.deployment_descriptor(&pk).unwrap();
        assert_eq!(descriptor.constructor_calldata, vec![pk]);
    }

    #[test]
    fn test_normalized_hex_has_leading_zeros() {
        let oz = OpenZeppelinAccount::new();
        let pk = Felt::from(1u64); // small key → address with leading zeros
        let descriptor = oz.deployment_descriptor(&pk).unwrap();
        let hex = descriptor.normalized_address_hex();
        // "0x" + 64 hex chars = 66 total
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
        let oz = OpenZeppelinAccount::with_class_hash(custom_hash);
        let pk = Felt::from(99u64);
        let descriptor = oz.deployment_descriptor(&pk).unwrap();
        assert_eq!(descriptor.class_hash, custom_hash);
        assert_eq!(descriptor.address, oz.calculate_address(&pk).unwrap());
    }
}
