//! Gateway runtime struct, constructors, canonical descriptor derivation,
//! request validation, and operation tracking helpers.

use crate::account_class::{resolve_account_class, to_salt_policy};
use crate::backend::GatewayBackend;
use crate::clock::{Clock, SystemClock};
use crate::errors::{map_domain_error, map_kms_error};
use crate::operations::OperationStore;
use crate::snapshot::SnapshotCache;
use crate::types::{GatewayResult, OperationRetentionPolicy, SecretResolver};
use krusty_kms_common::{ChainId, SecretFelt};
use krusty_kms_domain::{
    AccountDescriptor, CachePolicy, DeployMode, DerivationRequest, FeltHex, GatewayError,
    GatewayErrorCode, KeyDomain, OperationId, OperationKind, OperationLookupResult, OperationState,
    OperationStatus, Provenance,
};
use starknet_types_core::felt::Felt;
use tokio::sync::RwLock;

/// Gateway-global ceiling for snapshot cache entries.
/// Per-request `CachePolicy.max_entries` is deprecated and ignored for eviction.
const DEFAULT_SNAPSHOT_CACHE_MAX_ENTRIES: usize = 256;
/// Maximum accepted `WaitForAcceptance` timeout (15 minutes).
///
/// Transports serve requests sequentially (see the stdio oracle), so this is
/// also the worst case one request can monopolize the pipe. Callers that need
/// to track slower deployments should use `SubmitOnly` and poll
/// `GetOperationStatus` instead of holding a wait open.
const MAX_WAIT_TIMEOUT_MS: u64 = 15 * 60 * 1000;
/// Minimum accepted `WaitForAcceptance` poll interval: a caller-supplied
/// 1ms interval would turn the wait loop into an RPC flood.
const MIN_WAIT_POLL_INTERVAL_MS: u64 = 250;

/// Gateway runtime with explicit secret, chain, and clock dependencies.
pub struct Gateway<B, S, C = SystemClock> {
    pub(crate) backend: B,
    pub(crate) secret_resolver: S,
    pub(crate) clock: C,
    pub(crate) operations: RwLock<OperationStore>,
    pub(crate) snapshot_cache: RwLock<SnapshotCache>,
    /// Hard ceiling used for shared snapshot-cache eviction (not request-controlled).
    pub(crate) snapshot_cache_max_entries: usize,
}

impl<B, S> Gateway<B, S, SystemClock>
where
    B: GatewayBackend,
    S: SecretResolver,
{
    pub fn new(backend: B, secret_resolver: S) -> Self {
        Self::with_clock(backend, secret_resolver, SystemClock)
    }

    pub fn with_retention(
        backend: B,
        secret_resolver: S,
        operation_retention: OperationRetentionPolicy,
    ) -> Self {
        Self::with_clock_and_retention(backend, secret_resolver, SystemClock, operation_retention)
    }
}

impl<B, S, C> Gateway<B, S, C>
where
    B: GatewayBackend,
    S: SecretResolver,
    C: Clock,
{
    pub fn with_clock(backend: B, secret_resolver: S, clock: C) -> Self {
        Self::with_clock_and_retention(
            backend,
            secret_resolver,
            clock,
            OperationRetentionPolicy::default(),
        )
    }

    pub fn with_clock_and_retention(
        backend: B,
        secret_resolver: S,
        clock: C,
        operation_retention: OperationRetentionPolicy,
    ) -> Self {
        Self {
            backend,
            secret_resolver,
            clock,
            operations: RwLock::new(OperationStore::new(operation_retention)),
            snapshot_cache: RwLock::new(SnapshotCache::default()),
            snapshot_cache_max_entries: DEFAULT_SNAPSHOT_CACHE_MAX_ENTRIES,
        }
    }

    /// Return the latest known status for an operation id.
    pub async fn operation_status(&self, id: &OperationId) -> OperationLookupResult {
        let now_ms = self.clock.now_ms();
        match self.operations.write().await.get(id, now_ms) {
            Some(operation) => OperationLookupResult::Found { operation },
            None => OperationLookupResult::NotFound {
                operation_id: id.clone(),
            },
        }
    }

    pub(crate) async fn derive_account_descriptor(
        &self,
        request: &DerivationRequest,
    ) -> GatewayResult<(SecretFelt, AccountDescriptor)> {
        self.ensure_chain_matches(request.chain_id)?;
        request.validate().map_err(map_domain_error)?;

        if request.key_domain != KeyDomain::StarknetAccount {
            return Err(GatewayError::new(
                GatewayErrorCode::UnsupportedKeyDomain,
                false,
                Some(format!(
                    "derive/check/deploy gateway flows currently require {:?}, got {:?}",
                    KeyDomain::StarknetAccount,
                    request.key_domain
                )),
            ));
        }

        let private_key = self
            .secret_resolver
            .resolve_private_key(&request.secret, request.key_domain, request.path)
            .await?;

        let public_key = derive_public_key(&private_key)?;
        let account_class = resolve_account_class(&request.account_class, request.chain_id)?;
        let salt_policy = to_salt_policy(&request.salt_policy);
        let salt = salt_policy.resolve(&public_key);
        let class_hash = account_class.class_hash();
        let constructor_calldata = account_class.build_constructor_calldata(&public_key);
        let address = account_class
            .calculate_address(&public_key, salt_policy)
            .map_err(map_kms_error)?;

        let descriptor = AccountDescriptor {
            address: FeltHex::from_felt(address),
            public_key: FeltHex::from_felt(public_key),
            class_hash: FeltHex::from_felt(class_hash),
            salt: FeltHex::from_felt(salt),
            constructor_calldata: constructor_calldata
                .into_iter()
                .map(FeltHex::from_felt)
                .collect(),
            deployer_address: FeltHex::from_felt(Felt::ZERO),
            provenance: Provenance {
                chain_id: request.chain_id,
                key_domain: request.key_domain,
                derivation_path: request.path,
                class_hash: Some(FeltHex::from_felt(class_hash)),
            },
        };

        Ok((private_key, descriptor))
    }

    pub(crate) fn ensure_chain_matches(&self, chain_id: ChainId) -> GatewayResult<()> {
        if chain_id != self.backend.chain_id() {
            return Err(GatewayError::new(
                GatewayErrorCode::ChainMismatch,
                false,
                Some(format!(
                    "request targets {}, gateway backend is configured for {}",
                    chain_id,
                    self.backend.chain_id()
                )),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_cache_policy(&self, cache_policy: CachePolicy) -> GatewayResult<()> {
        if cache_policy.ttl_ms == 0 {
            return Err(GatewayError::new(
                GatewayErrorCode::InvalidCachePolicy,
                false,
                Some("cache ttl_ms must be greater than zero".to_string()),
            ));
        }
        // max_entries is deprecated for shared snapshot eviction but still
        // validated (> 0) for wire/API compatibility with CachePolicy::new.
        if cache_policy.max_entries == 0 {
            return Err(GatewayError::new(
                GatewayErrorCode::InvalidCachePolicy,
                false,
                Some("cache max_entries must be greater than zero".to_string()),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_wait_mode(&self, mode: DeployMode) -> GatewayResult<()> {
        if let DeployMode::WaitForAcceptance(wait) = mode {
            if wait.poll_interval_ms < MIN_WAIT_POLL_INTERVAL_MS {
                return Err(GatewayError::new(
                    GatewayErrorCode::InvalidWaitPolicy,
                    false,
                    Some(format!(
                        "wait poll_interval_ms must be at least {MIN_WAIT_POLL_INTERVAL_MS}"
                    )),
                ));
            }
            // The wait loop caps each sleep at the remaining deadline, but an
            // absurd interval still degrades liveness; bound it like the timeout.
            if wait.poll_interval_ms > MAX_WAIT_TIMEOUT_MS {
                return Err(GatewayError::new(
                    GatewayErrorCode::InvalidWaitPolicy,
                    false,
                    Some(format!(
                        "wait poll_interval_ms must be at most {MAX_WAIT_TIMEOUT_MS}"
                    )),
                ));
            }
            if wait.timeout_ms == 0 {
                return Err(GatewayError::new(
                    GatewayErrorCode::InvalidWaitPolicy,
                    false,
                    Some("wait timeout_ms must be greater than zero".to_string()),
                ));
            }
            // A bounded timeout keeps the poll loop schedulable (`Instant +
            // Duration` overflows on absurd values) and pins worst-case queue
            // occupancy for the FIFO operation backlog.
            if wait.timeout_ms > MAX_WAIT_TIMEOUT_MS {
                return Err(GatewayError::new(
                    GatewayErrorCode::InvalidWaitPolicy,
                    false,
                    Some(format!(
                        "wait timeout_ms must be at most {MAX_WAIT_TIMEOUT_MS}"
                    )),
                ));
            }
        }

        Ok(())
    }

    pub(crate) async fn begin_operation(
        &self,
        kind: OperationKind,
    ) -> GatewayResult<OperationStatus> {
        // Operation ids double as bearer handles for `GetOperationStatus`.
        // Sequential ids (`derive-1`, `sign-2`, ...) let any caller that can
        // reach the status endpoint enumerate and observe other callers'
        // operations; 128 bits of OS entropy keep ids unguessable while the
        // prefix keeps them readable in logs.
        let entropy: [u8; 16] = krusty_kms_crypto::try_random_bytes().map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::Internal,
                true,
                Some(format!("OS entropy source unavailable: {error}")),
            )
        })?;
        let id = OperationId::new(format!(
            "{}-{}",
            operation_prefix(kind),
            hex::encode(entropy)
        ))
        .map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::Internal,
                false,
                Some(format!("failed to generate operation id: {error}")),
            )
        })?;
        let status = OperationStatus {
            id: id.clone(),
            kind,
            state: OperationState::Queued,
            provenance: None,
        };
        let now_ms = self.clock.now_ms();
        self.operations.write().await.insert(status.clone(), now_ms);
        Ok(status)
    }

    pub(crate) async fn set_operation(
        &self,
        id: &OperationId,
        kind: OperationKind,
        state: OperationState,
        provenance: Option<Provenance>,
    ) -> OperationStatus {
        let status = OperationStatus {
            id: id.clone(),
            kind,
            state,
            provenance,
        };
        let now_ms = self.clock.now_ms();
        self.operations.write().await.insert(status.clone(), now_ms);
        status
    }

    pub(crate) async fn reject_operation(
        &self,
        queued: &OperationStatus,
        error: GatewayError,
        provenance: Option<Provenance>,
    ) {
        self.set_operation(
            &queued.id,
            queued.kind,
            OperationState::Rejected { error },
            provenance,
        )
        .await;
    }
}

fn derive_public_key(private_key: &SecretFelt) -> GatewayResult<Felt> {
    let signing_key = starknet_rust::signers::SigningKey::from_secret_scalar(rs_felt_from_core(
        *private_key.expose_secret(),
    ));
    Ok(core_felt_from_rs(signing_key.verifying_key().scalar()))
}

fn operation_prefix(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::DeriveAccount => "derive",
        OperationKind::CheckDeployment => "check",
        OperationKind::DeployAccount => "deploy",
        OperationKind::Sign => "sign",
        OperationKind::QueryAccountSnapshot => "snapshot",
    }
}

fn rs_felt_from_core(felt: Felt) -> starknet_rust::core::types::Felt {
    starknet_rust::core::types::Felt::from_bytes_be(&felt.to_bytes_be())
}

fn core_felt_from_rs(felt: starknet_rust::core::types::Felt) -> Felt {
    Felt::from_bytes_be(&felt.to_bytes_be())
}
