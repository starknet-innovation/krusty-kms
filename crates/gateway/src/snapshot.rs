//! Snapshot queries with explicit cache metadata and a bounded shared cache.

use crate::backend::GatewayBackend;
use crate::clock::Clock;
use crate::gateway::Gateway;
use crate::types::{GatewayResponse, GatewayResult, SecretResolver};
use krusty_kms_common::ChainId;
use krusty_kms_domain::{
    AccountSnapshot, AccountSnapshotRequest, BlockSelector, CacheMetadata, CachePolicy,
    CacheStatus, FeltHex, OperationKind, OperationState, OperationStatus, QueryMode,
    SnapshotBlockMetadata, TokenBalanceSnapshot,
};
use std::collections::{HashMap, VecDeque};

impl<B, S, C> Gateway<B, S, C>
where
    B: GatewayBackend,
    S: SecretResolver,
    C: Clock,
{
    /// Query a chain snapshot with explicit cache metadata and bounded stale fallback.
    pub async fn query_account_snapshot(
        &self,
        request: AccountSnapshotRequest,
    ) -> GatewayResult<GatewayResponse<AccountSnapshot>> {
        let queued = self
            .begin_operation(OperationKind::QueryAccountSnapshot)
            .await?;
        self.set_operation(&queued.id, queued.kind, OperationState::Running, None)
            .await;

        if let Err(error) = self.ensure_chain_matches(request.chain_id) {
            self.reject_operation(&queued, error.clone(), None).await;
            return Err(error);
        }
        if let Err(error) = self.validate_cache_policy(request.cache_policy) {
            self.reject_operation(&queued, error.clone(), None).await;
            return Err(error);
        }

        let key = SnapshotCacheKey::from_request(&request);
        let now_ms = self.clock.now_ms();
        let cached = self.snapshot_cache.read().await.entries.get(&key).cloned();

        if let Some(value) = cached_snapshot_response(&request, cached.as_ref(), now_ms) {
            let status = self
                .set_operation(&queued.id, queued.kind, OperationState::Completed, None)
                .await;
            return Ok(GatewayResponse {
                operation: status,
                value,
            });
        }

        self.refresh_snapshot(&queued, &request, key, cached, now_ms)
            .await
    }

    /// Refresh handling: fetch a fresh snapshot and cache it, serving a bounded
    /// stale entry instead when the backend fails.
    async fn refresh_snapshot(
        &self,
        queued: &OperationStatus,
        request: &AccountSnapshotRequest,
        key: SnapshotCacheKey,
        cached: Option<SnapshotCacheEntry>,
        now_ms: u64,
    ) -> GatewayResult<GatewayResponse<AccountSnapshot>> {
        match self.fetch_snapshot(request, now_ms).await {
            Ok(snapshot) => {
                // Eviction uses the gateway-global ceiling only.
                // `CachePolicy.max_entries` is deprecated and ignored here so a
                // single request cannot flush unrelated shared-cache entries.
                self.store_snapshot(key, snapshot.clone(), self.snapshot_cache_max_entries)
                    .await;
                let status = self
                    .set_operation(&queued.id, queued.kind, OperationState::Completed, None)
                    .await;
                Ok(GatewayResponse {
                    operation: status,
                    value: snapshot,
                })
            }
            Err(error) => {
                if let Some(value) = stale_snapshot_fallback(request, cached, now_ms) {
                    let status = self
                        .set_operation(&queued.id, queued.kind, OperationState::Completed, None)
                        .await;
                    return Ok(GatewayResponse {
                        operation: status,
                        value,
                    });
                }

                self.reject_operation(queued, error.clone(), None).await;
                Err(error)
            }
        }
    }

    async fn fetch_snapshot(
        &self,
        request: &AccountSnapshotRequest,
        generated_at_ms: u64,
    ) -> GatewayResult<AccountSnapshot> {
        let deployed = self
            .backend
            .check_deployed(&request.address, &request.block)
            .await?;
        let nonce = if deployed {
            Some(self.backend.nonce(&request.address, &request.block).await?)
        } else {
            None
        };

        let mut balances = Vec::with_capacity(request.tokens.len());
        for token in &request.tokens {
            let amount_raw = self
                .backend
                .token_balance(&request.address, token, &request.block)
                .await?;
            balances.push(TokenBalanceSnapshot {
                token: token.clone(),
                amount_raw,
            });
        }

        let block = match self.backend.block_metadata(&request.block).await {
            Ok(block) => block,
            Err(_) => SnapshotBlockMetadata {
                selector: request.block.clone(),
                block_hash: None,
                block_number: None,
            },
        };

        Ok(AccountSnapshot {
            address: request.address.clone(),
            deployment: if deployed {
                krusty_kms_domain::DeploymentState::Deployed
            } else {
                krusty_kms_domain::DeploymentState::Undeployed
            },
            nonce,
            balances,
            block,
            cache: CacheMetadata {
                status: CacheStatus::Miss,
                generated_at_ms,
                age_ms: 0,
            },
        })
    }

    async fn store_snapshot(
        &self,
        key: SnapshotCacheKey,
        snapshot: AccountSnapshot,
        max_entries: usize,
    ) {
        let mut cache = self.snapshot_cache.write().await;

        if !cache.entries.contains_key(&key) {
            cache.order.push_back(key.clone());
        }
        cache.entries.insert(
            key,
            SnapshotCacheEntry {
                generated_at_ms: snapshot.cache.generated_at_ms,
                snapshot,
            },
        );

        while cache.entries.len() > max_entries {
            if let Some(evicted) = cache.order.pop_front() {
                cache.entries.remove(&evicted);
            }
        }
    }
}

/// Server-side ceiling for per-request snapshot freshness (`ttl_ms`).
pub(crate) const MAX_SNAPSHOT_TTL_MS: u64 = 60 * 60 * 1000;
/// Server-side ceiling for serving entries past their TTL
/// (`stale_while_revalidate_ms`).
const MAX_SNAPSHOT_STALE_MS: u64 = 24 * 60 * 60 * 1000;

/// Cache lookup: serve a fresh `Hit` within the clamped TTL, or a `Stale`
/// entry for background views still inside the stale-while-revalidate window.
fn cached_snapshot_response(
    request: &AccountSnapshotRequest,
    cached: Option<&SnapshotCacheEntry>,
    now_ms: u64,
) -> Option<AccountSnapshot> {
    let entry = cached?;
    let age_ms = now_ms.saturating_sub(entry.generated_at_ms);
    // Server-side clamp: a caller-supplied `ttl_ms` is a hint, not a
    // license to serve arbitrarily old data as a fresh `Hit`.
    if age_ms <= request.cache_policy.ttl_ms.min(MAX_SNAPSHOT_TTL_MS) {
        return Some(apply_cache_metadata(
            entry.snapshot.clone(),
            CacheStatus::Hit,
            entry.generated_at_ms,
            age_ms,
        ));
    }

    if age_ms <= max_cache_age(request.cache_policy)
        && matches!(request.mode, QueryMode::BackgroundView)
    {
        return Some(apply_cache_metadata(
            entry.snapshot.clone(),
            CacheStatus::Stale,
            entry.generated_at_ms,
            age_ms,
        ));
    }

    None
}

/// Stale fallback: serve an expired entry still inside the bounded stale
/// window when a refresh fails.
fn stale_snapshot_fallback(
    request: &AccountSnapshotRequest,
    cached: Option<SnapshotCacheEntry>,
    now_ms: u64,
) -> Option<AccountSnapshot> {
    let entry = cached?;
    let age_ms = now_ms.saturating_sub(entry.generated_at_ms);
    if age_ms <= max_cache_age(request.cache_policy) {
        return Some(apply_cache_metadata(
            entry.snapshot,
            CacheStatus::Stale,
            entry.generated_at_ms,
            age_ms,
        ));
    }
    None
}

fn max_cache_age(policy: CachePolicy) -> u64 {
    // Clamp caller-controlled windows to server ceilings so no request can
    // keep an ancient entry eligible for `Stale` service indefinitely.
    policy
        .ttl_ms
        .min(MAX_SNAPSHOT_TTL_MS)
        .saturating_add(policy.stale_while_revalidate_ms.min(MAX_SNAPSHOT_STALE_MS))
}

fn apply_cache_metadata(
    mut snapshot: AccountSnapshot,
    status: CacheStatus,
    generated_at_ms: u64,
    age_ms: u64,
) -> AccountSnapshot {
    snapshot.cache = CacheMetadata {
        status,
        generated_at_ms,
        age_ms,
    };
    snapshot
}

#[derive(Default)]
pub(crate) struct SnapshotCache {
    entries: HashMap<SnapshotCacheKey, SnapshotCacheEntry>,
    order: VecDeque<SnapshotCacheKey>,
}

#[derive(Clone)]
struct SnapshotCacheEntry {
    generated_at_ms: u64,
    snapshot: AccountSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SnapshotCacheKey {
    chain_id: ChainId,
    address: FeltHex,
    block: CachedBlockSelector,
    tokens: Vec<CachedTrackedToken>,
}

impl SnapshotCacheKey {
    fn from_request(request: &AccountSnapshotRequest) -> Self {
        Self {
            chain_id: request.chain_id,
            address: request.address.clone(),
            block: CachedBlockSelector::from(&request.block),
            tokens: request
                .tokens
                .iter()
                .map(CachedTrackedToken::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CachedBlockSelector {
    Latest,
    Pending,
    Number(u64),
    Hash(FeltHex),
}

impl From<&BlockSelector> for CachedBlockSelector {
    fn from(value: &BlockSelector) -> Self {
        match value {
            BlockSelector::Latest => Self::Latest,
            BlockSelector::Pending => Self::Pending,
            BlockSelector::Number(number) => Self::Number(*number),
            BlockSelector::Hash(hash) => Self::Hash(hash.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CachedTrackedToken {
    symbol: String,
    address: FeltHex,
    decimals: u8,
}

impl From<&krusty_kms_domain::TrackedToken> for CachedTrackedToken {
    fn from(value: &krusty_kms_domain::TrackedToken) -> Self {
        Self {
            symbol: value.symbol.clone(),
            address: value.address.clone(),
            decimals: value.decimals,
        }
    }
}
