//! Public gateway contract types: results, secret resolution, and operation
//! retention policy.

use async_trait::async_trait;
use krusty_kms_common::SecretFelt;
use krusty_kms_domain::{GatewayError, GatewayErrorCode, KeyDomain, OperationStatus};
use zeroize::Zeroizing;

pub type GatewayResult<T> = Result<T, GatewayError>;

const DEFAULT_OPERATION_RETENTION_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const DEFAULT_OPERATION_RETENTION_MAX_ENTRIES: usize = 1_024;

/// Trusted-boundary dependency that resolves a private key for the requested domain/path.
///
/// # Trust model
///
/// The gateway (and the stdio oracle built on it) performs **no caller
/// authentication or tenant isolation**: any party that can invoke gateway
/// methods can derive and sign with every secret this resolver exposes.
/// `SecretRef` labels are global, not tenant-scoped. Deploy only behind a
/// trusted peer boundary (local supervisor, OS user isolation); never expose
/// to untrusted callers. See `docs/oracle-stdio-v1.md` § Trust Model.
#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve_private_key(
        &self,
        secret: &krusty_kms_domain::SecretRef,
        key_domain: KeyDomain,
        path: krusty_kms_domain::DerivationPath,
    ) -> GatewayResult<SecretFelt>;

    async fn resolve_nostr_private_key(
        &self,
        _secret: &krusty_kms_domain::SecretRef,
        _path: krusty_kms_domain::DerivationPath,
    ) -> GatewayResult<Zeroizing<[u8; 32]>> {
        Err(GatewayError::new(
            GatewayErrorCode::UnsupportedKeyDomain,
            false,
            Some("secret resolver does not support Nostr private keys".to_string()),
        ))
    }
}

/// Gateway method result bundled with the final tracked operation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayResponse<T> {
    pub operation: OperationStatus,
    pub value: T,
}

/// Retention policy for tracked operation state inside the long-lived gateway runtime.
///
/// Invariants:
/// - `ttl_ms > 0`
/// - `max_entries > 0`
///
/// The gateway does not promise durable operation history. Entries age into
/// `Expired` after `ttl_ms`, and the store may evict the oldest entries when it
/// exceeds `max_entries`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationRetentionPolicy {
    ttl_ms: u64,
    max_entries: usize,
}

impl OperationRetentionPolicy {
    pub fn new(ttl_ms: u64, max_entries: usize) -> Result<Self, OperationRetentionError> {
        if ttl_ms == 0 {
            return Err(OperationRetentionError::ZeroTtl);
        }
        if max_entries == 0 {
            return Err(OperationRetentionError::ZeroMaxEntries);
        }

        Ok(Self {
            ttl_ms,
            max_entries,
        })
    }

    #[must_use]
    pub const fn ttl_ms(self) -> u64 {
        self.ttl_ms
    }

    #[must_use]
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }
}

impl Default for OperationRetentionPolicy {
    fn default() -> Self {
        Self {
            ttl_ms: DEFAULT_OPERATION_RETENTION_TTL_MS,
            max_entries: DEFAULT_OPERATION_RETENTION_MAX_ENTRIES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationRetentionError {
    ZeroTtl,
    ZeroMaxEntries,
}

impl std::fmt::Display for OperationRetentionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroTtl => f.write_str("operation retention ttl_ms must be greater than zero"),
            Self::ZeroMaxEntries => {
                f.write_str("operation retention max_entries must be greater than zero")
            }
        }
    }
}

impl std::error::Error for OperationRetentionError {}
