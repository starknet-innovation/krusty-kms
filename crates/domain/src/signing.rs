//! Signing request/result domain types.

use crate::account::{DerivationPath, KeyDomain};
use crate::error::DomainError;
use crate::primitives::{FeltHex, HexBytes, SecretRef};
use krusty_kms_common::ChainId;
use serde::{Deserialize, Serialize};

/// High-level signing domain separation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StarkSignDomain {
    TransactionHash,
    TypedDataHash,
}

/// Stark-backed key domains that can produce Stark-curve signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StarkKeyDomain {
    StarknetAccount,
    TongoAccount,
}

impl StarkKeyDomain {
    pub const fn key_domain(self) -> KeyDomain {
        match self {
            Self::StarknetAccount => KeyDomain::StarknetAccount,
            Self::TongoAccount => KeyDomain::TongoAccount,
        }
    }
}

/// Raw byte message payload used for non-prehashed message signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawMessagePayload {
    Hex(HexBytes),
    Utf8(String),
}

/// Canonical signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignRequest {
    StarkHash {
        secret: SecretRef,
        key_domain: StarkKeyDomain,
        derivation_path: DerivationPath,
        chain_id: ChainId,
        domain: StarkSignDomain,
        hash: FeltHex,
        /// Dangerous opt-in for blind/pre-hashed Stark ECDSA signing.
        ///
        /// Defaults to `false`. When false, the request is rejected so callers
        /// must explicitly acknowledge raw-hash signing (prefer typed-data /
        /// structured sign paths when available).
        #[serde(default)]
        allow_raw_stark_hash: bool,
    },
    StarkRawMessage {
        secret: SecretRef,
        key_domain: StarkKeyDomain,
        derivation_path: DerivationPath,
        message: FeltHex,
        /// Dangerous opt-in for blind felt signing (same risk class as
        /// [`Self::StarkHash`] raw-hash signing). Defaults to `false`.
        #[serde(default)]
        allow_raw_stark_hash: bool,
    },
    NostrEvent {
        secret: SecretRef,
        derivation_path: DerivationPath,
        event_id: HexBytes,
    },
    NostrRawMessage {
        secret: SecretRef,
        derivation_path: DerivationPath,
        payload: RawMessagePayload,
    },
}

impl SignRequest {
    /// Validate structural invariants that are independent of runtime policy.
    pub fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::StarkHash {
                key_domain,
                derivation_path,
                allow_raw_stark_hash,
                ..
            } => {
                derivation_path.validate_for(key_domain.key_domain())?;
                if !allow_raw_stark_hash {
                    return Err(DomainError::InvalidSignRequest(
                        "stark_hash signing requires allow_raw_stark_hash=true; prefer typed/structured sign paths".to_string(),
                    ));
                }
            }
            Self::StarkRawMessage {
                key_domain,
                derivation_path,
                allow_raw_stark_hash,
                ..
            } => {
                derivation_path.validate_for(key_domain.key_domain())?;
                if !allow_raw_stark_hash {
                    return Err(DomainError::InvalidSignRequest(
                        "stark_raw_message signing requires allow_raw_stark_hash=true; prefer typed/structured sign paths".to_string(),
                    ));
                }
            }
            Self::NostrEvent {
                derivation_path,
                event_id,
                ..
            } => {
                derivation_path.validate_for(KeyDomain::NostrEvent)?;
                let _ = event_id.to_array::<32>()?;
            }
            Self::NostrRawMessage {
                derivation_path,
                payload,
                ..
            } => {
                derivation_path.validate_for(KeyDomain::NostrEvent)?;
                if let RawMessagePayload::Hex(bytes) = payload {
                    let _ = bytes.to_vec();
                }
            }
        }

        Ok(())
    }

    pub fn key_domain(&self) -> KeyDomain {
        match self {
            Self::StarkHash { key_domain, .. } | Self::StarkRawMessage { key_domain, .. } => {
                key_domain.key_domain()
            }
            Self::NostrEvent { .. } | Self::NostrRawMessage { .. } => KeyDomain::NostrEvent,
        }
    }

    pub fn derivation_path(&self) -> DerivationPath {
        match self {
            Self::StarkHash {
                derivation_path, ..
            }
            | Self::StarkRawMessage {
                derivation_path, ..
            }
            | Self::NostrEvent {
                derivation_path, ..
            }
            | Self::NostrRawMessage {
                derivation_path, ..
            } => *derivation_path,
        }
    }

    pub fn secret(&self) -> &SecretRef {
        match self {
            Self::StarkHash { secret, .. }
            | Self::StarkRawMessage { secret, .. }
            | Self::NostrEvent { secret, .. }
            | Self::NostrRawMessage { secret, .. } => secret,
        }
    }

    pub fn chain_id(&self) -> Option<ChainId> {
        match self {
            Self::StarkHash { chain_id, .. } => Some(*chain_id),
            Self::StarkRawMessage { .. }
            | Self::NostrEvent { .. }
            | Self::NostrRawMessage { .. } => None,
        }
    }
}

/// Typed signing result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum SignResult {
    StarkEcdsa {
        public_key: FeltHex,
        signature_r: FeltHex,
        signature_s: FeltHex,
    },
    NostrBip340 {
        public_key: HexBytes,
        signature: HexBytes,
    },
}
