//! Snapshot queries with explicit cache metadata and a bounded shared cache.

use crate::backend::GatewayBackend;
use crate::clock::Clock;
use crate::gateway::Gateway;
use crate::snapshot_cache::{
    cached_snapshot_response, quantize_down, stale_snapshot_fallback, SnapshotCacheEntry,
    SnapshotCacheKey, MAX_SNAPSHOT_TOKENS,
};
use crate::types::{GatewayResponse, GatewayResult, SecretResolver};
use krusty_kms_domain::{
    AccountSnapshot, AccountSnapshotRequest, CacheMetadata, CacheStatus, OperationKind,
    OperationState, OperationStatus, SnapshotBlockMetadata, TokenBalanceSnapshot,
};

pub(crate) use crate::snapshot_cache::SnapshotCache;

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
        // Each tracked token costs backend RPC calls; an unbounded list is a
        // request-amplification vector.
        if request.tokens.len() > MAX_SNAPSHOT_TOKENS {
            let error = krusty_kms_domain::GatewayError::new(
                krusty_kms_domain::GatewayErrorCode::InvalidRequest,
                false,
                Some(format!(
                    "snapshot request tracks {} tokens (maximum {MAX_SNAPSHOT_TOKENS})",
                    request.tokens.len()
                )),
            );
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
                self.store_snapshot(
                    key,
                    snapshot.clone(),
                    self.snapshot_cache_max_entries,
                    now_ms,
                )
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
            // Quantized like every other exposed timestamp, so "cache metadata
            // leaving the gateway is always quantized" holds as an invariant
            // rather than something each path has to remember. The cache entry
            // keeps the exact time, passed separately to `store_snapshot`.
            cache: CacheMetadata {
                status: CacheStatus::Miss,
                generated_at_ms: quantize_down(generated_at_ms),
                age_ms: 0,
            },
        })
    }

    /// Store a freshly fetched snapshot.
    ///
    /// `generated_at_ms` is the **exact** fetch time and must not be quantized:
    /// it is the base for every subsequent TTL and stale-window decision, and a
    /// coarsened base would let entries be served as fresh for up to one
    /// quantum past their real deadline. Only the copy exposed to callers is
    /// quantized.
    async fn store_snapshot(
        &self,
        key: SnapshotCacheKey,
        snapshot: AccountSnapshot,
        max_entries: usize,
        generated_at_ms: u64,
    ) {
        let mut cache = self.snapshot_cache.write().await;

        if !cache.entries.contains_key(&key) {
            cache.order.push_back(key.clone());
        }
        cache.entries.insert(
            key,
            SnapshotCacheEntry {
                generated_at_ms,
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
