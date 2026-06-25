//! OpenZeppelin Cairo multisig deployment descriptors.
//!
//! The OpenZeppelin multisig constructor is:
//!
//! ```text
//! constructor(quorum: u32, signers: Span<ContractAddress>)
//! ```
//!
//! Cairo serializes the span as a length prefix followed by each signer address,
//! so the canonical constructor calldata is:
//!
//! ```text
//! [quorum, signers.len(), signer_0, signer_1, ...]
//! ```
//!
//! This module is deliberately network-free. It validates deployment inputs and
//! computes the same counterfactual address that a deployer or UDC flow must use.

use crate::account::calculate_contract_address;
use crate::account_class::SaltPolicy;
use krusty_kms_common::{KmsError, Result};
use starknet_types_core::felt::Felt;
use std::collections::HashSet;

/// OpenZeppelin Cairo multisig contract class.
///
/// The class hash is caller-provided because OpenZeppelin ships the multisig as
/// a reusable governance component, not a globally declared account preset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenZeppelinMultisig {
    class_hash: Felt,
}

/// Deployment parameters for an OpenZeppelin Cairo multisig contract.
///
/// The descriptor keeps address derivation, constructor calldata, and deployment
/// salt tied together so callers can inspect and reuse the exact same values for
/// deployment and coordination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OzMultisigDeploymentDescriptor {
    pub address: Felt,
    pub class_hash: Felt,
    pub salt: Felt,
    pub constructor_calldata: Vec<Felt>,
    /// Always `Felt::ZERO` for counterfactual deployment.
    pub deployer_address: Felt,
    pub quorum: u32,
    pub signers: Vec<Felt>,
}

impl OzMultisigDeploymentDescriptor {
    /// Return the address as a zero-padded hex string (`0x` + 64 hex chars).
    #[must_use]
    pub fn normalized_address_hex(&self) -> String {
        format!("0x{:064x}", self.address)
    }
}

impl OpenZeppelinMultisig {
    /// Create a multisig descriptor helper from an explicit class hash.
    #[must_use]
    pub fn from_class_hash(class_hash: Felt) -> Self {
        Self { class_hash }
    }

    /// The contract class hash used for deployment address derivation.
    #[must_use]
    pub fn class_hash(&self) -> Felt {
        self.class_hash
    }

    /// Build canonical constructor calldata for the OpenZeppelin multisig.
    ///
    /// # Errors
    ///
    /// Returns [`KmsError::MultisigError`] when:
    /// - `quorum` is zero
    /// - there are no signers
    /// - `quorum` exceeds the number of unique signers
    /// - a signer is the zero address
    /// - a signer appears more than once
    pub fn build_constructor_calldata(quorum: u32, signers: &[Felt]) -> Result<Vec<Felt>> {
        validate_multisig_config(quorum, signers)?;

        let mut calldata = Vec::with_capacity(signers.len() + 2);
        calldata.push(Felt::from(quorum));
        calldata.push(Felt::from(signers.len() as u64));
        calldata.extend_from_slice(signers);
        Ok(calldata)
    }

    /// Build a deployment descriptor for a signer set and salt policy.
    ///
    /// Unlike single-owner accounts, the multisig does not have a public key
    /// from which a salt can be derived. Use `SaltPolicy::Zero` for a zero salt
    /// or `SaltPolicy::Explicit` for reproducible production deployments.
    pub fn deployment_descriptor(
        &self,
        quorum: u32,
        signers: &[Felt],
        salt_policy: SaltPolicy,
    ) -> Result<OzMultisigDeploymentDescriptor> {
        let constructor_calldata = Self::build_constructor_calldata(quorum, signers)?;
        let salt = match salt_policy {
            SaltPolicy::Explicit(salt) => salt,
            SaltPolicy::Zero => Felt::ZERO,
            SaltPolicy::PublicKey => {
                return Err(KmsError::MultisigError(
                    "public-key salt policy is invalid for multisig deployments".to_string(),
                ))
            }
        };
        let deployer_address = Felt::ZERO;
        let address = calculate_contract_address(
            &salt,
            &self.class_hash,
            &constructor_calldata,
            &deployer_address,
        )?;

        Ok(OzMultisigDeploymentDescriptor {
            address,
            class_hash: self.class_hash,
            salt,
            constructor_calldata,
            deployer_address,
            quorum,
            signers: signers.to_vec(),
        })
    }
}

fn validate_multisig_config(quorum: u32, signers: &[Felt]) -> Result<()> {
    if quorum == 0 {
        return Err(KmsError::MultisigError(
            "quorum must be greater than zero".to_string(),
        ));
    }
    if signers.is_empty() {
        return Err(KmsError::MultisigError(
            "at least one signer is required".to_string(),
        ));
    }
    if quorum as usize > signers.len() {
        return Err(KmsError::MultisigError(format!(
            "quorum {quorum} exceeds signer count {}",
            signers.len()
        )));
    }

    let mut seen = HashSet::with_capacity(signers.len());
    for signer in signers {
        if *signer == Felt::ZERO {
            return Err(KmsError::MultisigError(
                "signer address cannot be zero".to_string(),
            ));
        }
        if !seen.insert(*signer) {
            return Err(KmsError::MultisigError(format!(
                "duplicate signer address {signer:#x}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signers() -> Vec<Felt> {
        vec![Felt::from(11u64), Felt::from(22u64), Felt::from(33u64)]
    }

    #[test]
    fn test_multisig_constructor_calldata() {
        let signers = signers();
        let calldata = OpenZeppelinMultisig::build_constructor_calldata(2, &signers).unwrap();
        assert_eq!(
            calldata,
            vec![
                Felt::from(2u64),
                Felt::from(3u64),
                Felt::from(11u64),
                Felt::from(22u64),
                Felt::from(33u64),
            ]
        );
    }

    #[test]
    fn test_multisig_descriptor_is_deterministic() {
        let class_hash = Felt::from(0x1234u64);
        let multisig = OpenZeppelinMultisig::from_class_hash(class_hash);
        let salt = Felt::from(99u64);
        let first = multisig
            .deployment_descriptor(2, &signers(), SaltPolicy::Explicit(salt))
            .unwrap();
        let second = multisig
            .deployment_descriptor(2, &signers(), SaltPolicy::Explicit(salt))
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.class_hash, class_hash);
        assert_eq!(first.salt, salt);
    }

    #[test]
    fn test_multisig_descriptor_rejects_zero_quorum() {
        let multisig = OpenZeppelinMultisig::from_class_hash(Felt::from(0x1234u64));
        assert!(matches!(
            multisig.deployment_descriptor(0, &signers(), SaltPolicy::Zero),
            Err(KmsError::MultisigError(_))
        ));
    }

    #[test]
    fn test_multisig_descriptor_rejects_duplicate_signers() {
        let multisig = OpenZeppelinMultisig::from_class_hash(Felt::from(0x1234u64));
        let signers = vec![Felt::from(11u64), Felt::from(11u64)];
        assert!(matches!(
            multisig.deployment_descriptor(1, &signers, SaltPolicy::Zero),
            Err(KmsError::MultisigError(_))
        ));
    }

    #[test]
    fn test_multisig_descriptor_rejects_public_key_salt_policy() {
        let multisig = OpenZeppelinMultisig::from_class_hash(Felt::from(0x1234u64));
        assert!(matches!(
            multisig.deployment_descriptor(1, &signers(), SaltPolicy::PublicKey),
            Err(KmsError::MultisigError(_))
        ));
    }
}
