//! Bounded shared snapshot cache, TTL helpers, and exposed-metadata quantization.

use krusty_kms_common::ChainId;
use krusty_kms_domain::{
    AccountSnapshot, AccountSnapshotRequest, BlockSelector, CacheMetadata, CachePolicy,
    CacheStatus, FeltHex, QueryMode,
};
use std::collections::{HashMap, VecDeque};

/// Maximum tracked tokens per snapshot request: each token costs an RPC call,
/// so an unbounded caller-supplied list amplifies one request into arbitrary
/// backend load (M-11).
pub(crate) const MAX_SNAPSHOT_TOKENS: usize = 16;
/// Server-side ceiling for per-request snapshot freshness (`ttl_ms`).
pub(crate) const MAX_SNAPSHOT_TTL_MS: u64 = 60 * 60 * 1000;
/// Server-side ceiling for serving entries past their TTL
/// (`stale_while_revalidate_ms`).
const MAX_SNAPSHOT_STALE_MS: u64 = 24 * 60 * 60 * 1000;
/// Quantum for cache timestamps exposed on shared-cache responses.
///
/// The snapshot cache is shared across all callers of a gateway, so a `Hit`
/// carrying the exact `generated_at_ms` tells one caller precisely when some
/// *other* caller last queried the same address — a cross-tenant activity
/// timing oracle. Quantizing the exposed metadata to a coarse grid keeps the
/// freshness contract useful while destroying the oracle's precision.
pub(crate) const SNAPSHOT_TIME_QUANTUM_MS: u64 = 5_000;

/// Cache lookup: serve a fresh `Hit` within the clamped TTL, or a `Stale`
/// entry for background views still inside the stale-while-revalidate window.
pub(crate) fn cached_snapshot_response(
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
            now_ms,
        ));
    }

    if age_ms <= max_cache_age(request.cache_policy)
        && matches!(request.mode, QueryMode::BackgroundView)
    {
        return Some(apply_cache_metadata(
            entry.snapshot.clone(),
            CacheStatus::Stale,
            entry.generated_at_ms,
            now_ms,
        ));
    }

    None
}

/// Stale fallback: serve an expired entry still inside the bounded stale
/// window when a refresh fails.
pub(crate) fn stale_snapshot_fallback(
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
            now_ms,
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
    now_ms: u64,
) -> AccountSnapshot {
    // Freshness/TTL decisions above use exact values; only the metadata that
    // leaves the gateway is quantized.
    //
    // `age_ms` is deliberately NOT `quantize(now - generated_at)`. Quantizing
    // the true age still leaks the exact generation time, because the bucket
    // *transition* is itself the signal: an attacker polling a shared entry
    // sees age flip 5000 -> 10000 precisely when `now` crosses
    // `generated_at + 5000`, and they know their own clock, so the transition
    // pins `generated_at` to their polling resolution — recovering exactly what
    // quantizing `generated_at_ms` was meant to hide.
    //
    // Instead both fields are derived from independently quantized buckets:
    //   generated = floor(generated_at / Q)
    //   age       = ceil(now / Q) - generated
    // Every term is something the caller already possesses (its own clock, plus
    // the `generated` bucket returned right here), so `age_ms` conveys no
    // additional information, and its transitions now happen at absolute
    // wall-clock boundaries — simultaneously for every cache entry, and so
    // independent of any particular entry's generation time.
    //
    // Rounding `now` up keeps the reported age conservative: it may over-state
    // age by up to one quantum but never under-states it, so a consumer cannot
    // conclude an entry is fresher than it really is.
    let generated_bucket = quantize_down(generated_at_ms);
    snapshot.cache = CacheMetadata {
        status,
        generated_at_ms: generated_bucket,
        age_ms: quantize_up(now_ms).saturating_sub(generated_bucket),
    };
    snapshot
}

pub(crate) fn quantize_down(value_ms: u64) -> u64 {
    value_ms - (value_ms % SNAPSHOT_TIME_QUANTUM_MS)
}

fn quantize_up(value_ms: u64) -> u64 {
    match value_ms % SNAPSHOT_TIME_QUANTUM_MS {
        0 => value_ms,
        rem => value_ms.saturating_add(SNAPSHOT_TIME_QUANTUM_MS - rem),
    }
}

#[derive(Default)]
pub(crate) struct SnapshotCache {
    pub(crate) entries: HashMap<SnapshotCacheKey, SnapshotCacheEntry>,
    pub(crate) order: VecDeque<SnapshotCacheKey>,
}

#[derive(Clone)]
pub(crate) struct SnapshotCacheEntry {
    pub(crate) generated_at_ms: u64,
    pub(crate) snapshot: AccountSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SnapshotCacheKey {
    chain_id: ChainId,
    address: FeltHex,
    block: CachedBlockSelector,
    tokens: Vec<CachedTrackedToken>,
}

impl SnapshotCacheKey {
    pub(crate) fn from_request(request: &AccountSnapshotRequest) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use krusty_kms_domain::SnapshotBlockMetadata;

    fn snapshot() -> AccountSnapshot {
        AccountSnapshot {
            address: FeltHex::parse("0x1").unwrap(),
            deployment: krusty_kms_domain::DeploymentState::Undeployed,
            nonce: None,
            balances: vec![],
            block: SnapshotBlockMetadata {
                selector: BlockSelector::Latest,
                block_hash: None,
                block_number: None,
            },
            cache: CacheMetadata {
                status: CacheStatus::Miss,
                generated_at_ms: 0,
                age_ms: 0,
            },
        }
    }

    fn exposed(generated_at_ms: u64, now_ms: u64) -> (u64, u64) {
        let out = apply_cache_metadata(snapshot(), CacheStatus::Hit, generated_at_ms, now_ms);
        (out.cache.generated_at_ms, out.cache.age_ms)
    }

    /// The security property: two entries generated at different exact times
    /// inside the same quantum must be indistinguishable in exposed metadata at
    /// every observation time. If any exposed field varied with the sub-quantum
    /// part of the generation time, a caller polling a shared entry could
    /// recover that exact time and the cross-tenant activity oracle would
    /// survive quantization.
    #[test]
    fn exposed_metadata_is_blind_to_sub_quantum_generation_time() {
        let q = SNAPSHOT_TIME_QUANTUM_MS;
        // Same bucket [q, 2q): first ms, middle, last ms.
        for now_ms in (q..(6 * q)).step_by(97) {
            let first = exposed(q, now_ms);
            let middle = exposed(q + q / 2, now_ms);
            let last = exposed(2 * q - 1, now_ms);
            assert_eq!(
                first, middle,
                "generation time within a bucket leaked at now={now_ms}"
            );
            assert_eq!(
                first, last,
                "generation time within a bucket leaked at now={now_ms}"
            );
        }
    }

    /// Age must change only at absolute wall-clock quantum boundaries, the same
    /// instants for every cache entry. The previous implementation quantized the
    /// true age, so the bucket flipped at `generated_at + q` — an offset that
    /// depends on the entry, which is precisely what made the transition
    /// observable.
    #[test]
    fn age_transitions_are_independent_of_generation_time() {
        let q = SNAPSHOT_TIME_QUANTUM_MS;

        // Collect the instants at which the reported age changes, for several
        // entries generated at different points inside one bucket.
        let transitions_for = |generated_at: u64| {
            let mut transitions = vec![];
            let mut previous = exposed(generated_at, q).1;
            for now_ms in (q + 1)..(5 * q) {
                let age = exposed(generated_at, now_ms).1;
                if age != previous {
                    transitions.push(now_ms);
                    previous = age;
                }
            }
            transitions
        };

        let baseline = transitions_for(q);
        assert!(!baseline.is_empty(), "expected age to advance at all");

        // The invariant that matters: the transition instants are the same for
        // every entry in the bucket. The previous implementation quantized the
        // true age, so the bucket flipped at `generated_at + q` — an offset that
        // differs per entry, which is exactly what made it observable.
        for generated_at in [q + 1, q + q / 3, 2 * q - 1] {
            assert_eq!(
                transitions_for(generated_at),
                baseline,
                "generated_at={generated_at} produced entry-dependent transitions"
            );
        }

        // And they sit on absolute wall-clock boundaries (first ms past each).
        for t in &baseline {
            assert_eq!(
                t % q,
                1,
                "transition at {t} is not on an absolute quantum boundary"
            );
        }
    }

    /// Reported age must never under-state the true age: a consumer must not be
    /// able to conclude an entry is fresher than it actually is.
    #[test]
    fn reported_age_is_never_optimistic() {
        let q = SNAPSHOT_TIME_QUANTUM_MS;
        for generated_at in [0, 1, q - 1, q, q + 7, 3 * q + 123] {
            for now_ms in [
                generated_at,
                generated_at + 1,
                generated_at + q,
                generated_at + 4 * q,
            ] {
                let (_, reported) = exposed(generated_at, now_ms);
                let truth = now_ms.saturating_sub(generated_at);
                assert!(
                    reported >= truth,
                    "reported age {reported} under-states true age {truth} \
                     (generated_at={generated_at}, now={now_ms})"
                );
            }
        }
    }

    /// A clock that moves backwards (skew, or a test clock rewound) must not
    /// underflow the age subtraction.
    #[test]
    fn backwards_clock_does_not_underflow() {
        let (generated, age) = exposed(10 * SNAPSHOT_TIME_QUANTUM_MS, 0);
        assert_eq!(generated, 10 * SNAPSHOT_TIME_QUANTUM_MS);
        assert_eq!(age, 0);
    }
}
