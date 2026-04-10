//! Long-lived gateway runtime for TUIs and app integrations.
//!
//! Inputs:
//! - typed domain requests from `krusty-kms-domain`
//! - a `SecretResolver` that keeps secret material inside the trusted boundary
//! - a `GatewayBackend` that isolates Starknet RPC and deployment effects
//!
//! Outputs:
//! - typed domain results
//! - tracked `OperationStatus` transitions
//! - explicit cache metadata for snapshot queries
//!
//! Invariants:
//! - gateway methods validate chain and derivation-domain consistency before I/O
//! - derive/check/deploy share one canonical descriptor path
//! - runtime state is localized to operation tracking and bounded snapshot cache

mod backend;
mod clock;

pub use backend::{DeployExecution, GatewayBackend, StarknetGatewayBackend};
pub use clock::{Clock, SystemClock};

use async_trait::async_trait;
use krusty_kms::{
    sign_nostr_event_id, sign_nostr_message, sign_stark_hash, AccountClass, ArgentAccount,
    BraavosAccount, OpenZeppelinAccount, SaltPolicy,
};
use krusty_kms_common::{ChainId, KmsError, SecretFelt};
use krusty_kms_domain::{
    AccountClassKind, AccountClassSpec, AccountDescriptor, AccountSnapshot, AccountSnapshotRequest,
    BlockSelector, CacheMetadata, CachePolicy, CacheStatus, CheckDeploymentResult,
    DeployAccountRequest, DeployAccountResult, DeployMode, DerivationRequest, DomainError, FeltHex,
    GatewayError, GatewayErrorCode, HexBytes, KeyDomain, OperationId, OperationKind,
    OperationLookupResult, OperationState, OperationStatus, Provenance, QueryMode,
    RawMessagePayload, SaltPolicySpec, SignRequest, SignResult, SnapshotBlockMetadata,
    TokenBalanceSnapshot,
};
use starknet_types_core::felt::Felt;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

pub type GatewayResult<T> = Result<T, GatewayError>;

const DEFAULT_OPERATION_RETENTION_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const DEFAULT_OPERATION_RETENTION_MAX_ENTRIES: usize = 1_024;

/// Trusted-boundary dependency that resolves a private key for the requested domain/path.
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

/// Gateway runtime with explicit secret, chain, and clock dependencies.
pub struct Gateway<B, S, C = SystemClock> {
    backend: B,
    secret_resolver: S,
    clock: C,
    operations: RwLock<OperationStore>,
    snapshot_cache: RwLock<SnapshotCache>,
    next_operation: AtomicU64,
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
            next_operation: AtomicU64::new(1),
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

    /// Derive a canonical account descriptor using the trusted secret boundary.
    pub async fn derive_account(
        &self,
        request: DerivationRequest,
    ) -> GatewayResult<GatewayResponse<AccountDescriptor>> {
        let queued = self.begin_operation(OperationKind::DeriveAccount).await?;
        self.set_operation(&queued.id, queued.kind, OperationState::Running, None)
            .await;

        match self.derive_account_descriptor(&request).await {
            Ok((_, account)) => {
                let status = self
                    .set_operation(
                        &queued.id,
                        queued.kind,
                        OperationState::Completed,
                        Some(account.provenance.clone()),
                    )
                    .await;
                Ok(GatewayResponse {
                    operation: status,
                    value: account,
                })
            }
            Err(error) => {
                self.reject_operation(&queued, error.clone(), None).await;
                Err(error)
            }
        }
    }

    /// Check deployment state for the canonical account derived from `request`.
    pub async fn check_deployment(
        &self,
        request: DerivationRequest,
    ) -> GatewayResult<GatewayResponse<CheckDeploymentResult>> {
        let queued = self.begin_operation(OperationKind::CheckDeployment).await?;
        self.set_operation(&queued.id, queued.kind, OperationState::Running, None)
            .await;

        match self.derive_account_descriptor(&request).await {
            Ok((_, account)) => match self
                .backend
                .check_deployed(&account.address, &BlockSelector::Latest)
                .await
            {
                Ok(true) => {
                    let result = CheckDeploymentResult {
                        account: account.clone(),
                        deployment: krusty_kms_domain::DeploymentState::Deployed,
                    };
                    let status = self
                        .set_operation(
                            &queued.id,
                            queued.kind,
                            OperationState::Completed,
                            Some(account.provenance.clone()),
                        )
                        .await;
                    Ok(GatewayResponse {
                        operation: status,
                        value: result,
                    })
                }
                Ok(false) => {
                    let result = CheckDeploymentResult {
                        account: account.clone(),
                        deployment: krusty_kms_domain::DeploymentState::Undeployed,
                    };
                    let status = self
                        .set_operation(
                            &queued.id,
                            queued.kind,
                            OperationState::Completed,
                            Some(account.provenance.clone()),
                        )
                        .await;
                    Ok(GatewayResponse {
                        operation: status,
                        value: result,
                    })
                }
                Err(error) => {
                    self.reject_operation(&queued, error.clone(), Some(account.provenance))
                        .await;
                    Err(error)
                }
            },
            Err(error) => {
                self.reject_operation(&queued, error.clone(), None).await;
                Err(error)
            }
        }
    }

    /// Deploy an OpenZeppelin account using the same canonical descriptor as derive/check.
    pub async fn deploy_account(
        &self,
        request: DeployAccountRequest,
    ) -> GatewayResult<GatewayResponse<DeployAccountResult>> {
        let queued = self.begin_operation(OperationKind::DeployAccount).await?;
        self.set_operation(&queued.id, queued.kind, OperationState::Running, None)
            .await;

        if let Err(error) = self.validate_wait_mode(request.mode) {
            self.reject_operation(&queued, error.clone(), None).await;
            return Err(error);
        }

        match self.derive_account_descriptor(&request.derivation).await {
            Ok((private_key, account)) => {
                if !matches!(
                    request.derivation.account_class.kind,
                    AccountClassKind::OpenZeppelin
                ) {
                    let error = GatewayError::new(
                        GatewayErrorCode::UnsupportedAccountClass,
                        false,
                        Some(
                            "deploy_account currently supports OpenZeppelin accounts only"
                                .to_string(),
                        ),
                    );
                    self.reject_operation(&queued, error.clone(), Some(account.provenance))
                        .await;
                    return Err(error);
                }

                match self
                    .backend
                    .deploy_open_zeppelin(&private_key, &account, request.mode)
                    .await
                {
                    Ok(DeployExecution::AlreadyDeployed) => {
                        let result = DeployAccountResult {
                            account: account.clone(),
                            deployment: krusty_kms_domain::DeploymentState::Deployed,
                            already_deployed: true,
                        };
                        let status = self
                            .set_operation(
                                &queued.id,
                                queued.kind,
                                OperationState::Completed,
                                Some(account.provenance.clone()),
                            )
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: result,
                        })
                    }
                    Ok(DeployExecution::Submitted { tx_hash }) => {
                        let result = DeployAccountResult {
                            account: account.clone(),
                            deployment: krusty_kms_domain::DeploymentState::Deploying {
                                tx_hash: tx_hash.clone(),
                            },
                            already_deployed: false,
                        };
                        let status = self
                            .set_operation(
                                &queued.id,
                                queued.kind,
                                OperationState::Submitted {
                                    tx_hash: tx_hash.clone(),
                                },
                                Some(account.provenance.clone()),
                            )
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: result,
                        })
                    }
                    Ok(DeployExecution::Accepted { tx_hash }) => {
                        let result = DeployAccountResult {
                            account: account.clone(),
                            deployment: krusty_kms_domain::DeploymentState::Deployed,
                            already_deployed: false,
                        };
                        let status = self
                            .set_operation(
                                &queued.id,
                                queued.kind,
                                OperationState::Accepted { tx_hash },
                                Some(account.provenance.clone()),
                            )
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: result,
                        })
                    }
                    Err(error) => {
                        self.reject_operation(&queued, error.clone(), Some(account.provenance))
                            .await;
                        Err(error)
                    }
                }
            }
            Err(error) => {
                self.reject_operation(&queued, error.clone(), None).await;
                Err(error)
            }
        }
    }

    /// Sign a typed payload using the explicit domain-separated secret boundary.
    pub async fn sign(&self, request: SignRequest) -> GatewayResult<GatewayResponse<SignResult>> {
        let queued = self.begin_operation(OperationKind::Sign).await?;
        self.set_operation(&queued.id, queued.kind, OperationState::Running, None)
            .await;

        if let Err(error) = request.validate().map_err(map_domain_error) {
            self.reject_operation(&queued, error.clone(), None).await;
            return Err(error);
        }

        let provenance = sign_provenance(&request);

        match &request {
            SignRequest::StarkHash {
                secret,
                key_domain,
                derivation_path,
                hash,
                ..
            }
            | SignRequest::StarkRawMessage {
                secret,
                key_domain,
                derivation_path,
                message: hash,
            } => {
                let private_key = match self
                    .secret_resolver
                    .resolve_private_key(secret, key_domain.key_domain(), *derivation_path)
                    .await
                {
                    Ok(key) => key,
                    Err(error) => {
                        self.reject_operation(&queued, error.clone(), None).await;
                        return Err(error);
                    }
                };

                match sign_stark_hash(private_key.expose_secret(), &hash.to_felt()) {
                    Ok(signed) => {
                        let status = self
                            .set_operation(
                                &queued.id,
                                queued.kind,
                                OperationState::Completed,
                                provenance.clone(),
                            )
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: SignResult::StarkEcdsa {
                                public_key: FeltHex::from_felt(signed.public_key),
                                signature_r: FeltHex::from_felt(signed.r),
                                signature_s: FeltHex::from_felt(signed.s),
                            },
                        })
                    }
                    Err(error) => {
                        let gateway_error = map_kms_error(error);
                        self.reject_operation(&queued, gateway_error.clone(), provenance)
                            .await;
                        Err(gateway_error)
                    }
                }
            }
            SignRequest::NostrEvent {
                secret,
                derivation_path,
                event_id,
            } => {
                let private_key = match self
                    .secret_resolver
                    .resolve_nostr_private_key(secret, *derivation_path)
                    .await
                {
                    Ok(key) => key,
                    Err(error) => {
                        self.reject_operation(&queued, error.clone(), None).await;
                        return Err(error);
                    }
                };

                let event_id = match event_id.to_array::<32>() {
                    Ok(value) => value,
                    Err(error) => {
                        let gateway_error = map_domain_error(error);
                        self.reject_operation(&queued, gateway_error.clone(), None)
                            .await;
                        return Err(gateway_error);
                    }
                };

                match sign_nostr_event_id(&private_key, &event_id) {
                    Ok(signed) => {
                        let status = self
                            .set_operation(&queued.id, queued.kind, OperationState::Completed, None)
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: SignResult::NostrBip340 {
                                public_key: HexBytes::from_bytes(&signed.public_key),
                                signature: HexBytes::from_bytes(&signed.signature),
                            },
                        })
                    }
                    Err(error) => {
                        let gateway_error = map_kms_error(error);
                        self.reject_operation(&queued, gateway_error.clone(), None)
                            .await;
                        Err(gateway_error)
                    }
                }
            }
            SignRequest::NostrRawMessage {
                secret,
                derivation_path,
                payload,
            } => {
                let private_key = match self
                    .secret_resolver
                    .resolve_nostr_private_key(secret, *derivation_path)
                    .await
                {
                    Ok(key) => key,
                    Err(error) => {
                        self.reject_operation(&queued, error.clone(), None).await;
                        return Err(error);
                    }
                };

                let message = match payload {
                    RawMessagePayload::Utf8(value) => value.as_bytes().to_vec(),
                    RawMessagePayload::Hex(bytes) => bytes.to_vec(),
                };

                match sign_nostr_message(&private_key, &message) {
                    Ok(signed) => {
                        let status = self
                            .set_operation(&queued.id, queued.kind, OperationState::Completed, None)
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: SignResult::NostrBip340 {
                                public_key: HexBytes::from_bytes(&signed.public_key),
                                signature: HexBytes::from_bytes(&signed.signature),
                            },
                        })
                    }
                    Err(error) => {
                        let gateway_error = map_kms_error(error);
                        self.reject_operation(&queued, gateway_error.clone(), None)
                            .await;
                        Err(gateway_error)
                    }
                }
            }
        }
    }

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

        if let Some(entry) = &cached {
            let age_ms = now_ms.saturating_sub(entry.generated_at_ms);
            if age_ms <= request.cache_policy.ttl_ms {
                let value = apply_cache_metadata(
                    entry.snapshot.clone(),
                    CacheStatus::Hit,
                    entry.generated_at_ms,
                    age_ms,
                );
                let status = self
                    .set_operation(&queued.id, queued.kind, OperationState::Completed, None)
                    .await;
                return Ok(GatewayResponse {
                    operation: status,
                    value,
                });
            }

            if age_ms <= max_cache_age(request.cache_policy)
                && matches!(request.mode, QueryMode::BackgroundView)
            {
                let value = apply_cache_metadata(
                    entry.snapshot.clone(),
                    CacheStatus::Stale,
                    entry.generated_at_ms,
                    age_ms,
                );
                let status = self
                    .set_operation(&queued.id, queued.kind, OperationState::Completed, None)
                    .await;
                return Ok(GatewayResponse {
                    operation: status,
                    value,
                });
            }
        }

        match self.fetch_snapshot(&request, now_ms).await {
            Ok(snapshot) => {
                self.store_snapshot(key, snapshot.clone(), request.cache_policy.max_entries)
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
                if let Some(entry) = cached {
                    let age_ms = now_ms.saturating_sub(entry.generated_at_ms);
                    if age_ms <= max_cache_age(request.cache_policy) {
                        let value = apply_cache_metadata(
                            entry.snapshot,
                            CacheStatus::Stale,
                            entry.generated_at_ms,
                            age_ms,
                        );
                        let status = self
                            .set_operation(&queued.id, queued.kind, OperationState::Completed, None)
                            .await;
                        return Ok(GatewayResponse {
                            operation: status,
                            value,
                        });
                    }
                }

                self.reject_operation(&queued, error.clone(), None).await;
                Err(error)
            }
        }
    }

    async fn derive_account_descriptor(
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

    fn ensure_chain_matches(&self, chain_id: ChainId) -> GatewayResult<()> {
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

    fn validate_cache_policy(&self, cache_policy: CachePolicy) -> GatewayResult<()> {
        if cache_policy.ttl_ms == 0 {
            return Err(GatewayError::new(
                GatewayErrorCode::InvalidCachePolicy,
                false,
                Some("cache ttl_ms must be greater than zero".to_string()),
            ));
        }
        if cache_policy.max_entries == 0 {
            return Err(GatewayError::new(
                GatewayErrorCode::InvalidCachePolicy,
                false,
                Some("cache max_entries must be greater than zero".to_string()),
            ));
        }
        Ok(())
    }

    fn validate_wait_mode(&self, mode: DeployMode) -> GatewayResult<()> {
        if let DeployMode::WaitForAcceptance(wait) = mode {
            if wait.poll_interval_ms == 0 {
                return Err(GatewayError::new(
                    GatewayErrorCode::InvalidWaitPolicy,
                    false,
                    Some("wait poll_interval_ms must be greater than zero".to_string()),
                ));
            }
            if wait.timeout_ms == 0 {
                return Err(GatewayError::new(
                    GatewayErrorCode::InvalidWaitPolicy,
                    false,
                    Some("wait timeout_ms must be greater than zero".to_string()),
                ));
            }
        }

        Ok(())
    }

    async fn begin_operation(&self, kind: OperationKind) -> GatewayResult<OperationStatus> {
        let sequence = self.next_operation.fetch_add(1, Ordering::Relaxed);
        let id = OperationId::new(format!("{}-{}", operation_prefix(kind), sequence)).map_err(
            |error| {
                GatewayError::new(
                    GatewayErrorCode::Internal,
                    false,
                    Some(format!("failed to generate operation id: {error}")),
                )
            },
        )?;
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

    async fn set_operation(
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

    async fn reject_operation(
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

pub(crate) fn map_kms_error(error: KmsError) -> GatewayError {
    match error {
        KmsError::AccountNotDeployed(message) => {
            GatewayError::new(GatewayErrorCode::Undeployed, false, Some(message))
        }
        KmsError::ContractNotFound(message) => {
            GatewayError::new(GatewayErrorCode::NotFound, false, Some(message))
        }
        KmsError::InsufficientBalance {
            available,
            required,
        } => GatewayError::new(
            GatewayErrorCode::InsufficientBalance,
            false,
            Some(format!("available={}, required={}", available, required)),
        ),
        KmsError::InsufficientFeeBalance(message) => {
            GatewayError::new(GatewayErrorCode::InsufficientFee, false, Some(message))
        }
        KmsError::InvalidClassHash(message) => {
            GatewayError::new(GatewayErrorCode::InvalidClassHash, false, Some(message))
        }
        KmsError::InvalidDerivationPath(message) => GatewayError::new(
            GatewayErrorCode::InvalidDerivationPath,
            false,
            Some(message),
        ),
        KmsError::Timeout(message) => {
            GatewayError::new(GatewayErrorCode::Timeout, true, Some(message))
        }
        KmsError::InvalidMnemonic(message) | KmsError::InvalidPrivateKey(message) => {
            GatewayError::new(GatewayErrorCode::SecretUnavailable, false, Some(message))
        }
        KmsError::RpcError(message) | KmsError::FeeEstimationFailed(message) => {
            GatewayError::new(GatewayErrorCode::ProviderTransport, true, Some(message))
        }
        KmsError::TransactionError(message) => classify_transaction_error(message),
        KmsError::TransactionReverted(message) => classify_reverted_transaction_error(message),
        KmsError::AlreadyDeployed(message) => {
            GatewayError::new(GatewayErrorCode::InvalidRequest, false, Some(message))
        }
        KmsError::InvalidPublicKey(message)
        | KmsError::CryptoError(message)
        | KmsError::SerializationError(message)
        | KmsError::DeserializationError(message)
        | KmsError::InvalidAmount(message)
        | KmsError::StarknetCryptoError(message)
        | KmsError::InvalidProof(message)
        | KmsError::StakingError(message)
        | KmsError::ControllerError(message) => {
            GatewayError::new(GatewayErrorCode::InvalidRequest, false, Some(message))
        }
        KmsError::HexError(error) => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(error.to_string()),
        ),
        KmsError::JsonError(error) => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(error.to_string()),
        ),
        KmsError::PointAtInfinity => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some("derived public key is point at infinity".to_string()),
        ),
    }
}

fn map_domain_error(error: DomainError) -> GatewayError {
    match error {
        DomainError::InvalidDerivationPath(message) => GatewayError::new(
            GatewayErrorCode::InvalidDerivationPath,
            false,
            Some(message),
        ),
        DomainError::InvalidCachePolicy(message) => GatewayError::new(
            GatewayErrorCode::InvalidCachePolicy,
            false,
            Some(message.to_string()),
        ),
        DomainError::InvalidWaitPolicy(message) => GatewayError::new(
            GatewayErrorCode::InvalidWaitPolicy,
            false,
            Some(message.to_string()),
        ),
        DomainError::InvalidFeltHex(message) => {
            GatewayError::new(GatewayErrorCode::InvalidRequest, false, Some(message))
        }
        DomainError::InvalidHexBytes(message) | DomainError::InvalidSignRequest(message) => {
            GatewayError::new(GatewayErrorCode::InvalidRequest, false, Some(message))
        }
        DomainError::EmptyField { field } => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(format!("field {} must not be empty", field)),
        ),
    }
}

fn classify_transaction_error(message: String) -> GatewayError {
    let lower = message.to_lowercase();
    let code = if lower.contains("nonce") {
        GatewayErrorCode::NonceMismatch
    } else if lower.contains("constructor") || lower.contains("calldata") {
        GatewayErrorCode::ConstructorCalldataMismatch
    } else if lower.contains("class hash") {
        GatewayErrorCode::InvalidClassHash
    } else {
        GatewayErrorCode::RpcDegraded
    };

    let retryable = matches!(
        code,
        GatewayErrorCode::NonceMismatch | GatewayErrorCode::RpcDegraded
    );

    GatewayError::new(code, retryable, Some(message))
}

fn classify_reverted_transaction_error(message: String) -> GatewayError {
    let lower = message.to_lowercase();
    let code = if lower.contains("constructor") || lower.contains("calldata") {
        GatewayErrorCode::ConstructorCalldataMismatch
    } else if lower.contains("class hash") {
        GatewayErrorCode::InvalidClassHash
    } else {
        GatewayErrorCode::InvalidRequest
    };

    GatewayError::new(code, false, Some(message))
}

fn derive_public_key(private_key: &SecretFelt) -> GatewayResult<Felt> {
    let signing_key = starknet_rust::signers::SigningKey::from_secret_scalar(rs_felt_from_core(
        *private_key.expose_secret(),
    ));
    Ok(core_felt_from_rs(signing_key.verifying_key().scalar()))
}

fn sign_provenance(request: &SignRequest) -> Option<Provenance> {
    request.chain_id().map(|chain_id| Provenance {
        chain_id,
        key_domain: request.key_domain(),
        derivation_path: request.derivation_path(),
        class_hash: None,
    })
}

fn resolve_account_class(
    spec: &AccountClassSpec,
    chain_id: ChainId,
) -> GatewayResult<ResolvedAccountClass> {
    match spec.kind {
        AccountClassKind::OpenZeppelin => {
            let account = match (&spec.class_hash, &spec.source_label) {
                (Some(class_hash), _) => OpenZeppelinAccount::from_class_hash(class_hash.to_felt()),
                (None, Some(version)) => {
                    OpenZeppelinAccount::from_manifest(chain_id, version).map_err(map_kms_error)?
                }
                (None, None) => OpenZeppelinAccount::latest(chain_id).map_err(map_kms_error)?,
            };
            Ok(ResolvedAccountClass::OpenZeppelin(account))
        }
        AccountClassKind::Argent => {
            if spec.source_label.is_some() {
                return Err(GatewayError::new(
                    GatewayErrorCode::UnsupportedAccountClass,
                    false,
                    Some("Argent account resolution does not support source_label".to_string()),
                ));
            }

            Ok(ResolvedAccountClass::Argent(match &spec.class_hash {
                Some(class_hash) => ArgentAccount::with_class_hash(class_hash.to_felt()),
                None => ArgentAccount::new(),
            }))
        }
        AccountClassKind::Braavos => {
            if spec.source_label.is_some() {
                return Err(GatewayError::new(
                    GatewayErrorCode::UnsupportedAccountClass,
                    false,
                    Some("Braavos account resolution does not support source_label".to_string()),
                ));
            }

            Ok(ResolvedAccountClass::Braavos(match &spec.class_hash {
                Some(class_hash) => BraavosAccount::with_class_hash(class_hash.to_felt()),
                None => BraavosAccount::new(),
            }))
        }
    }
}

fn to_salt_policy(spec: &SaltPolicySpec) -> SaltPolicy {
    match spec {
        SaltPolicySpec::PublicKey => SaltPolicy::PublicKey,
        SaltPolicySpec::Zero => SaltPolicy::Zero,
        SaltPolicySpec::Explicit(salt) => SaltPolicy::Explicit(salt.to_felt()),
    }
}

fn max_cache_age(policy: CachePolicy) -> u64 {
    policy
        .ttl_ms
        .saturating_add(policy.stale_while_revalidate_ms)
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

enum ResolvedAccountClass {
    OpenZeppelin(OpenZeppelinAccount),
    Argent(ArgentAccount),
    Braavos(BraavosAccount),
}

impl ResolvedAccountClass {
    fn as_account_class(&self) -> &dyn AccountClass {
        match self {
            Self::OpenZeppelin(account) => account,
            Self::Argent(account) => account,
            Self::Braavos(account) => account,
        }
    }

    fn class_hash(&self) -> Felt {
        self.as_account_class().class_hash()
    }

    fn build_constructor_calldata(&self, public_key: &Felt) -> Vec<Felt> {
        self.as_account_class()
            .build_constructor_calldata(public_key)
    }

    fn calculate_address(
        &self,
        public_key: &Felt,
        salt_policy: SaltPolicy,
    ) -> Result<Felt, KmsError> {
        self.as_account_class()
            .calculate_address(public_key, salt_policy)
    }
}

struct OperationStore {
    retention: OperationRetentionPolicy,
    entries: HashMap<OperationId, OperationEntry>,
    next_revision: u64,
}

struct OperationEntry {
    status: OperationStatus,
    updated_at_ms: u64,
    revision: u64,
}

impl OperationStore {
    fn new(retention: OperationRetentionPolicy) -> Self {
        Self {
            retention,
            entries: HashMap::new(),
            next_revision: 1,
        }
    }

    fn get(&mut self, id: &OperationId, now_ms: u64) -> Option<OperationStatus> {
        self.prune(now_ms);
        self.entries.get(id).map(|entry| entry.status.clone())
    }

    fn insert(&mut self, status: OperationStatus, now_ms: u64) {
        let revision = self.next_revision;
        self.next_revision = self.next_revision.saturating_add(1);
        self.entries.insert(
            status.id.clone(),
            OperationEntry {
                status,
                updated_at_ms: now_ms,
                revision,
            },
        );
        self.prune(now_ms);
    }

    fn prune(&mut self, now_ms: u64) {
        let ttl_ms = self.retention.ttl_ms();
        for entry in self.entries.values_mut() {
            if matches!(entry.status.state, OperationState::Expired) {
                continue;
            }

            if now_ms.saturating_sub(entry.updated_at_ms) > ttl_ms {
                entry.status.state = OperationState::Expired;
            }
        }

        let max_entries = self.retention.max_entries();
        if self.entries.len() <= max_entries {
            return;
        }

        let mut by_age: Vec<_> = self
            .entries
            .iter()
            .map(|(id, entry)| {
                (
                    id.clone(),
                    !matches!(entry.status.state, OperationState::Expired),
                    entry.revision,
                )
            })
            .collect();
        by_age.sort_unstable_by_key(|(_, active, revision)| (*active, *revision));

        let remove_count = self.entries.len() - max_entries;
        for (id, _, _) in by_age.into_iter().take(remove_count) {
            self.entries.remove(&id);
        }
    }
}

#[derive(Default)]
struct SnapshotCache {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use std::sync::Mutex;

    #[derive(Default)]
    struct TestClock {
        now_ms: AtomicU64,
    }

    impl TestClock {
        fn set(&self, value: u64) {
            self.now_ms.store(value, Ordering::Relaxed);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::Relaxed)
        }
    }

    struct FixedSecretResolver {
        private_key: SecretFelt,
        nostr_private_key: [u8; 32],
    }

    #[async_trait]
    impl SecretResolver for FixedSecretResolver {
        async fn resolve_private_key(
            &self,
            _secret: &krusty_kms_domain::SecretRef,
            _key_domain: KeyDomain,
            _path: krusty_kms_domain::DerivationPath,
        ) -> GatewayResult<SecretFelt> {
            Ok(self.private_key.clone())
        }

        async fn resolve_nostr_private_key(
            &self,
            _secret: &krusty_kms_domain::SecretRef,
            _path: krusty_kms_domain::DerivationPath,
        ) -> GatewayResult<Zeroizing<[u8; 32]>> {
            Ok(Zeroizing::new(self.nostr_private_key))
        }
    }

    struct FakeBackend {
        chain_id: ChainId,
        deployed: bool,
        nonce: FeltHex,
        balances: BTreeMap<String, String>,
        block: SnapshotBlockMetadata,
        deploy_execution: Mutex<DeployExecution>,
        deployment_checks: AtomicUsize,
        nonce_reads: AtomicUsize,
        balance_reads: AtomicUsize,
        block_reads: AtomicUsize,
    }

    #[async_trait]
    impl GatewayBackend for FakeBackend {
        fn chain_id(&self) -> ChainId {
            self.chain_id
        }

        async fn check_deployed(
            &self,
            _address: &FeltHex,
            _block: &BlockSelector,
        ) -> GatewayResult<bool> {
            self.deployment_checks.fetch_add(1, Ordering::Relaxed);
            Ok(self.deployed)
        }

        async fn deploy_open_zeppelin(
            &self,
            _private_key: &SecretFelt,
            _account: &AccountDescriptor,
            _mode: DeployMode,
        ) -> GatewayResult<DeployExecution> {
            Ok(self.deploy_execution.lock().unwrap().clone())
        }

        async fn nonce(
            &self,
            _address: &FeltHex,
            _block: &BlockSelector,
        ) -> GatewayResult<FeltHex> {
            self.nonce_reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.nonce.clone())
        }

        async fn token_balance(
            &self,
            _address: &FeltHex,
            token: &krusty_kms_domain::TrackedToken,
            _block: &BlockSelector,
        ) -> GatewayResult<String> {
            self.balance_reads.fetch_add(1, Ordering::Relaxed);
            Ok(self
                .balances
                .get(&token.symbol)
                .cloned()
                .unwrap_or_default())
        }

        async fn block_metadata(
            &self,
            _block: &BlockSelector,
        ) -> GatewayResult<SnapshotBlockMetadata> {
            self.block_reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.block.clone())
        }
    }

    fn gateway(
        clock: TestClock,
        deploy_execution: DeployExecution,
    ) -> Gateway<FakeBackend, FixedSecretResolver, TestClock> {
        gateway_with_retention(clock, deploy_execution, OperationRetentionPolicy::default())
    }

    fn gateway_with_retention(
        clock: TestClock,
        deploy_execution: DeployExecution,
        retention: OperationRetentionPolicy,
    ) -> Gateway<FakeBackend, FixedSecretResolver, TestClock> {
        Gateway::with_clock_and_retention(
            FakeBackend {
                chain_id: ChainId::Sepolia,
                deployed: true,
                nonce: FeltHex::parse("0x11").unwrap(),
                balances: BTreeMap::from([("STRK".to_string(), "42".to_string())]),
                block: SnapshotBlockMetadata {
                    selector: BlockSelector::Latest,
                    block_hash: Some(FeltHex::parse("0xabc").unwrap()),
                    block_number: Some(100),
                },
                deploy_execution: Mutex::new(deploy_execution),
                deployment_checks: AtomicUsize::new(0),
                nonce_reads: AtomicUsize::new(0),
                balance_reads: AtomicUsize::new(0),
                block_reads: AtomicUsize::new(0),
            },
            FixedSecretResolver {
                private_key: SecretFelt::new(Felt::from(123u64)),
                nostr_private_key: [
                    0x1d, 0xce, 0x8d, 0x2e, 0xc6, 0x18, 0x4c, 0xca, 0x94, 0x33, 0xf8, 0xf7, 0xb2,
                    0x70, 0x2d, 0x90, 0x14, 0x93, 0x66, 0x27, 0xce, 0x0f, 0x50, 0x92, 0x6f, 0x47,
                    0x1e, 0x52, 0x94, 0x6d, 0x0f, 0x4c,
                ],
            },
            clock,
            retention,
        )
    }

    fn derivation_request() -> DerivationRequest {
        DerivationRequest {
            secret: krusty_kms_domain::SecretRef::new("demo-secret").unwrap(),
            key_domain: KeyDomain::StarknetAccount,
            chain_id: ChainId::Sepolia,
            path: krusty_kms_domain::DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 0,
            },
            account_class: AccountClassSpec {
                kind: AccountClassKind::OpenZeppelin,
                class_hash: None,
                source_label: None,
            },
            salt_policy: SaltPolicySpec::PublicKey,
        }
    }

    fn snapshot_request(mode: QueryMode) -> AccountSnapshotRequest {
        AccountSnapshotRequest {
            chain_id: ChainId::Sepolia,
            address: FeltHex::parse("0x123").unwrap(),
            tokens: vec![krusty_kms_domain::TrackedToken {
                symbol: "STRK".to_string(),
                address: FeltHex::parse("0x456").unwrap(),
                decimals: 18,
            }],
            block: BlockSelector::Latest,
            mode,
            cache_policy: CachePolicy::new(1_000, 5_000, 8).unwrap(),
        }
    }

    fn nostr_sign_request() -> SignRequest {
        SignRequest::NostrEvent {
            secret: krusty_kms_domain::SecretRef::new("nostr-secret").unwrap(),
            derivation_path: krusty_kms_domain::DerivationPath {
                coin_type: 1237,
                account_index: 0,
                address_index: 7,
            },
            event_id: HexBytes::parse(
                "6c3fd336b5457a0f2b74959f177a5c5e7f9ab75cdb4ab7a3ec7aaf1e2a3d2b13",
            )
            .unwrap(),
        }
    }

    fn raw_nostr_sign_request() -> SignRequest {
        SignRequest::NostrRawMessage {
            secret: krusty_kms_domain::SecretRef::new("nostr-secret").unwrap(),
            derivation_path: krusty_kms_domain::DerivationPath {
                coin_type: 1237,
                account_index: 0,
                address_index: 7,
            },
            payload: RawMessagePayload::Utf8("hello nostr".to_string()),
        }
    }

    fn stark_sign_request() -> SignRequest {
        SignRequest::StarkHash {
            secret: krusty_kms_domain::SecretRef::new("stark-secret").unwrap(),
            key_domain: krusty_kms_domain::StarkKeyDomain::StarknetAccount,
            derivation_path: krusty_kms_domain::DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 2,
            },
            chain_id: ChainId::Sepolia,
            domain: krusty_kms_domain::StarkSignDomain::TransactionHash,
            hash: FeltHex::parse("0x1234").unwrap(),
        }
    }

    #[tokio::test]
    async fn derive_account_returns_descriptor_and_final_status() {
        let clock = TestClock::default();
        let gateway = gateway(clock, DeployExecution::AlreadyDeployed);

        let response = gateway.derive_account(derivation_request()).await.unwrap();

        assert_eq!(response.operation.kind, OperationKind::DeriveAccount);
        assert_eq!(response.operation.state, OperationState::Completed);
        assert_eq!(response.value.provenance.chain_id, ChainId::Sepolia);
        assert!(response.value.address.as_str().starts_with("0x"));
        assert_eq!(response.value.constructor_calldata.len(), 1);
    }

    #[tokio::test]
    async fn deploy_submit_only_maps_to_submitted_state() {
        let clock = TestClock::default();
        let tx_hash = FeltHex::parse("0xdead").unwrap();
        let gateway = gateway(
            clock,
            DeployExecution::Submitted {
                tx_hash: tx_hash.clone(),
            },
        );

        let response = gateway
            .deploy_account(DeployAccountRequest {
                derivation: derivation_request(),
                mode: DeployMode::SubmitOnly,
            })
            .await
            .unwrap();

        assert_eq!(
            response.operation.state,
            OperationState::Submitted {
                tx_hash: tx_hash.clone()
            }
        );
        assert_eq!(
            response.value.deployment,
            krusty_kms_domain::DeploymentState::Deploying { tx_hash }
        );

        let stored = gateway.operation_status(&response.operation.id).await;
        assert_eq!(
            stored,
            OperationLookupResult::Found {
                operation: response.operation.clone()
            }
        );
    }

    #[tokio::test]
    async fn query_account_snapshot_uses_stale_cache_for_background_mode() {
        let clock = TestClock::default();
        clock.set(1_000);
        let gateway = gateway(clock, DeployExecution::AlreadyDeployed);

        let first = gateway
            .query_account_snapshot(snapshot_request(QueryMode::ActiveView))
            .await
            .unwrap();
        assert_eq!(first.value.cache.status, CacheStatus::Miss);

        gateway.clock.set(2_500);
        let stale = gateway
            .query_account_snapshot(snapshot_request(QueryMode::BackgroundView))
            .await
            .unwrap();
        assert_eq!(stale.value.cache.status, CacheStatus::Stale);
        assert_eq!(stale.value.cache.generated_at_ms, 1_000);

        let checks_after_stale = gateway.backend.deployment_checks.load(Ordering::Relaxed);
        assert_eq!(checks_after_stale, 1);

        let refreshed = gateway
            .query_account_snapshot(snapshot_request(QueryMode::ActiveView))
            .await
            .unwrap();
        assert_eq!(refreshed.value.cache.status, CacheStatus::Miss);
        assert_eq!(gateway.backend.deployment_checks.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn derive_account_rejects_wrong_coin_type() {
        let clock = TestClock::default();
        let gateway = gateway(clock, DeployExecution::AlreadyDeployed);
        let mut request = derivation_request();
        request.path.coin_type = 5454;

        let error = gateway.derive_account(request).await.unwrap_err();
        assert_eq!(error.code, GatewayErrorCode::InvalidDerivationPath);
        assert!(!error.retryable);
    }

    #[tokio::test]
    async fn sign_returns_nostr_signature_and_tracks_completion() {
        let clock = TestClock::default();
        let gateway = gateway(clock, DeployExecution::AlreadyDeployed);

        let response = gateway.sign(nostr_sign_request()).await.unwrap();

        assert_eq!(response.operation.kind, OperationKind::Sign);
        assert_eq!(response.operation.state, OperationState::Completed);

        match response.value {
            SignResult::NostrBip340 {
                public_key,
                signature,
            } => {
                assert_eq!(public_key.as_str().len(), 64);
                assert_eq!(signature.as_str().len(), 128);
            }
            other => panic!("unexpected sign result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_supports_stark_hash_domains_with_chain_provenance() {
        let clock = TestClock::default();
        let gateway = gateway(clock, DeployExecution::AlreadyDeployed);
        let response = gateway.sign(stark_sign_request()).await.unwrap();

        assert_eq!(response.operation.kind, OperationKind::Sign);
        assert_eq!(
            response.operation.provenance.as_ref().unwrap().chain_id,
            ChainId::Sepolia
        );

        match response.value {
            SignResult::StarkEcdsa {
                public_key,
                signature_r,
                signature_s,
            } => {
                assert!(public_key.as_str().starts_with("0x"));
                assert!(signature_r.as_str().starts_with("0x"));
                assert!(signature_s.as_str().starts_with("0x"));
            }
            other => panic!("unexpected sign result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_supports_raw_nostr_messages() {
        let clock = TestClock::default();
        let gateway = gateway(clock, DeployExecution::AlreadyDeployed);

        let response = gateway.sign(raw_nostr_sign_request()).await.unwrap();

        match response.value {
            SignResult::NostrBip340 {
                public_key,
                signature,
            } => {
                assert_eq!(public_key.as_str().len(), 64);
                assert_eq!(signature.as_str().len(), 128);
            }
            other => panic!("unexpected sign result: {other:?}"),
        }
    }

    #[test]
    fn operation_retention_policy_rejects_zero_values() {
        assert_eq!(
            OperationRetentionPolicy::new(0, 1),
            Err(OperationRetentionError::ZeroTtl)
        );
        assert_eq!(
            OperationRetentionPolicy::new(1, 0),
            Err(OperationRetentionError::ZeroMaxEntries)
        );
    }

    #[tokio::test]
    async fn operation_status_evicts_entries_past_ttl() {
        let clock = TestClock::default();
        clock.set(1_000);
        let gateway = gateway_with_retention(
            clock,
            DeployExecution::AlreadyDeployed,
            OperationRetentionPolicy::new(100, 8).unwrap(),
        );

        let response = gateway.derive_account(derivation_request()).await.unwrap();
        assert_eq!(
            gateway.operation_status(&response.operation.id).await,
            OperationLookupResult::Found {
                operation: response.operation.clone()
            }
        );

        gateway.clock.set(1_101);
        assert_eq!(
            gateway.operation_status(&response.operation.id).await,
            OperationLookupResult::Found {
                operation: OperationStatus {
                    id: response.operation.id.clone(),
                    kind: response.operation.kind,
                    state: OperationState::Expired,
                    provenance: response.operation.provenance.clone(),
                }
            }
        );
    }

    #[tokio::test]
    async fn operation_status_evicts_oldest_entries_when_capacity_is_exceeded() {
        let clock = TestClock::default();
        let gateway = gateway_with_retention(
            clock,
            DeployExecution::AlreadyDeployed,
            OperationRetentionPolicy::new(60_000, 2).unwrap(),
        );

        let first = gateway.derive_account(derivation_request()).await.unwrap();
        let second = gateway
            .check_deployment(derivation_request())
            .await
            .unwrap();
        let third = gateway.sign(nostr_sign_request()).await.unwrap();

        assert_eq!(
            gateway.operation_status(&first.operation.id).await,
            OperationLookupResult::NotFound {
                operation_id: first.operation.id.clone()
            }
        );
        assert_eq!(
            gateway.operation_status(&second.operation.id).await,
            OperationLookupResult::Found {
                operation: second.operation.clone()
            }
        );
        assert_eq!(
            gateway.operation_status(&third.operation.id).await,
            OperationLookupResult::Found {
                operation: third.operation.clone()
            }
        );
    }
}
