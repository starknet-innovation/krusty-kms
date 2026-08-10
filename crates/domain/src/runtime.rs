//! Runtime query, cache, deploy, and operation-tracking domain types.

use crate::account::{AccountDescriptor, DeploymentState, DerivationRequest, Provenance};
use crate::error::{DomainError, GatewayError};
use crate::primitives::{FeltHex, OperationId};
use krusty_kms_common::ChainId;
use serde::{Deserialize, Serialize};

/// Screen mode informs polling/cache aggressiveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryMode {
    ActiveView,
    BackgroundView,
}

/// Block selector used in runtime chain queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockSelector {
    Latest,
    Pending,
    Number(u64),
    Hash(FeltHex),
}

/// A token the caller wants included in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedToken {
    pub symbol: String,
    pub address: FeltHex,
    pub decimals: u8,
}

/// Cache behavior contract exposed to integrators.
///
/// # Deprecation notice
///
/// [`Self::max_entries`] is **deprecated**. Gateway snapshot eviction uses a
/// process-global ceiling and ignores per-request `max_entries` so one client
/// cannot flush another client's cache. The field remains on the wire for
/// compatibility and must still be `> 0` when constructing via [`Self::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePolicy {
    pub ttl_ms: u64,
    pub stale_while_revalidate_ms: u64,
    /// Deprecated: ignored for gateway snapshot-cache eviction (global ceiling).
    #[doc(alias = "deprecated_max_entries")]
    pub max_entries: usize,
}

impl CachePolicy {
    /// Construct a cache policy.
    ///
    /// `max_entries` is retained for API/wire compatibility but is **deprecated**
    /// and ignored by the gateway shared snapshot cache.
    pub fn new(
        ttl_ms: u64,
        stale_while_revalidate_ms: u64,
        max_entries: usize,
    ) -> Result<Self, DomainError> {
        if ttl_ms == 0 {
            return Err(DomainError::InvalidCachePolicy(
                "ttl_ms must be greater than zero",
            ));
        }
        if max_entries == 0 {
            return Err(DomainError::InvalidCachePolicy(
                "max_entries must be greater than zero",
            ));
        }

        Ok(Self {
            ttl_ms,
            stale_while_revalidate_ms,
            max_entries,
        })
    }
}

/// Polling policy for runtime operations that optionally wait for completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitPolicy {
    pub poll_interval_ms: u64,
    pub timeout_ms: u64,
}

impl WaitPolicy {
    pub fn new(poll_interval_ms: u64, timeout_ms: u64) -> Result<Self, DomainError> {
        if poll_interval_ms == 0 {
            return Err(DomainError::InvalidWaitPolicy(
                "poll_interval_ms must be greater than zero",
            ));
        }
        if timeout_ms == 0 {
            return Err(DomainError::InvalidWaitPolicy(
                "timeout_ms must be greater than zero",
            ));
        }

        Ok(Self {
            poll_interval_ms,
            timeout_ms,
        })
    }
}

/// Whether deploy should stop after submission or wait for acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeployMode {
    SubmitOnly,
    WaitForAcceptance(WaitPolicy),
}

/// Canonical deploy request that preserves derive/deploy consistency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployAccountRequest {
    pub derivation: DerivationRequest,
    pub mode: DeployMode,
}

/// Typed deploy result for one derived account target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployAccountResult {
    pub account: AccountDescriptor,
    pub deployment: DeploymentState,
    pub already_deployed: bool,
}

/// Cache provenance for a runtime response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheStatus {
    Miss,
    Hit,
    Stale,
}

/// Cache metadata reported with runtime responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub status: CacheStatus,
    pub generated_at_ms: u64,
    pub age_ms: u64,
}

/// Query request for a single account snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSnapshotRequest {
    pub chain_id: ChainId,
    pub address: FeltHex,
    pub tokens: Vec<TrackedToken>,
    pub block: BlockSelector,
    pub mode: QueryMode,
    pub cache_policy: CachePolicy,
}

/// Balance metadata for one tracked token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBalanceSnapshot {
    pub token: TrackedToken,
    /// Raw integer amount represented as a decimal string.
    pub amount_raw: String,
}

/// Block metadata attached to a snapshot response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBlockMetadata {
    pub selector: BlockSelector,
    pub block_hash: Option<FeltHex>,
    pub block_number: Option<u64>,
}

/// Typed account snapshot for TUI screens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSnapshot {
    pub address: FeltHex,
    pub deployment: DeploymentState,
    pub nonce: Option<FeltHex>,
    pub balances: Vec<TokenBalanceSnapshot>,
    pub block: SnapshotBlockMetadata,
    pub cache: CacheMetadata,
}

/// High-level operation family submitted to a gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationKind {
    DeriveAccount,
    CheckDeployment,
    DeployAccount,
    Sign,
    QueryAccountSnapshot,
}

/// Typed lifecycle state for long-running operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationState {
    Queued,
    Running,
    Completed,
    Submitted { tx_hash: FeltHex },
    Accepted { tx_hash: FeltHex },
    Rejected { error: GatewayError },
    Expired,
}

/// Status event emitted for one tracked operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationStatus {
    pub id: OperationId,
    pub kind: OperationKind,
    pub state: OperationState,
    pub provenance: Option<Provenance>,
}
