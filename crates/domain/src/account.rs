//! Account derivation and deployment domain types.

use crate::error::{DomainError, GatewayError};
use crate::primitives::{FeltHex, SecretRef};
use krusty_kms_common::ChainId;
use serde::{Deserialize, Serialize};

/// Domain-separated key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyDomain {
    StarknetAccount,
    TongoAccount,
    NostrEvent,
}

impl KeyDomain {
    /// The expected BIP-44 coin type for this key domain.
    pub const fn expected_coin_type(self) -> u32 {
        match self {
            Self::StarknetAccount => 9004,
            Self::TongoAccount => 5454,
            Self::NostrEvent => 1237,
        }
    }
}

/// BIP-44 path coordinates relevant to the SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationPath {
    pub coin_type: u32,
    pub account_index: u32,
    pub address_index: u32,
}

impl DerivationPath {
    /// Validate that this path matches the expected coin type for `domain`.
    pub fn validate_for(self, domain: KeyDomain) -> Result<Self, DomainError> {
        if self.coin_type != domain.expected_coin_type() {
            return Err(DomainError::InvalidDerivationPath(format!(
                "coin_type {} does not match {:?} domain (expected {})",
                self.coin_type,
                domain,
                domain.expected_coin_type()
            )));
        }

        Ok(self)
    }
}

/// Deployment salt policy exposed to integrators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SaltPolicySpec {
    PublicKey,
    Zero,
    Explicit(FeltHex),
}

/// Supported Starknet account class families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountClassKind {
    OpenZeppelin,
    Argent,
    Braavos,
}

/// Caller-supplied account class selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountClassSpec {
    pub kind: AccountClassKind,
    /// Optional explicit class hash overriding the preset/default source.
    pub class_hash: Option<FeltHex>,
    /// Optional source label for provenance, such as a manifest version.
    pub source_label: Option<String>,
    /// Dangerous opt-in: allow a class hash that is not on the known allowlist.
    ///
    /// Defaults to `false`. When false, gateway/oracle derive/deploy reject
    /// arbitrary explicit class hashes. This flag cannot waive an unrecognised
    /// Argent class: Argent constructor calldata is version-specific, so those
    /// hashes are rejected even when the flag is `true`.
    #[serde(default)]
    pub allow_unlisted_class_hash: bool,
}

/// Canonical account derivation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationRequest {
    pub secret: SecretRef,
    pub key_domain: KeyDomain,
    pub chain_id: ChainId,
    pub path: DerivationPath,
    pub account_class: AccountClassSpec,
    pub salt_policy: SaltPolicySpec,
}

impl DerivationRequest {
    /// Validate domain-level invariants before runtime use.
    pub fn validate(&self) -> Result<(), DomainError> {
        self.path.validate_for(self.key_domain)?;
        Ok(())
    }
}

/// Provenance attached to deterministic outputs and runtime events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub chain_id: ChainId,
    pub key_domain: KeyDomain,
    pub derivation_path: DerivationPath,
    pub class_hash: Option<FeltHex>,
}

/// Canonical derived account metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDescriptor {
    pub address: FeltHex,
    pub public_key: FeltHex,
    pub class_hash: FeltHex,
    pub salt: FeltHex,
    pub constructor_calldata: Vec<FeltHex>,
    pub deployer_address: FeltHex,
    pub provenance: Provenance,
}

/// Typed deployment state for runtime queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentState {
    Undeployed,
    Deploying { tx_hash: FeltHex },
    Deployed,
    Rejected { error: GatewayError },
}

/// Result of checking whether a derived account is deployed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckDeploymentResult {
    pub account: AccountDescriptor,
    pub deployment: DeploymentState,
}
