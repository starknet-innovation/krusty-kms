//! Pure integration-domain contracts for TUI and gateway integrations.
//!
//! This crate intentionally contains no networking, clocks, filesystem access,
//! async runtime, or global mutable state. It exists to stabilize the typed
//! request/result/error surface that higher-level adapters and transports can
//! build on without re-inventing protocol glue.

pub mod oracle;

use krusty_kms_common::ChainId;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use std::fmt;
use thiserror::Error;

pub use oracle::{
    GetOperationStatusRequest, OperationLookupResult, OracleCommand, OracleCommandName,
    OracleOutcome, OracleRequest, OracleResponse, OracleResult, ProtocolInfo, RequestId,
    TrackedCommandResult,
};

/// Validation errors for domain-contract values.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid felt hex: {0}")]
    InvalidFeltHex(String),
    #[error("invalid hex bytes: {0}")]
    InvalidHexBytes(String),
    #[error("invalid {field}: value must not be empty")]
    EmptyField { field: &'static str },
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),
    #[error("invalid cache policy: {0}")]
    InvalidCachePolicy(&'static str),
    #[error("invalid wait policy: {0}")]
    InvalidWaitPolicy(&'static str),
    #[error("invalid sign request: {0}")]
    InvalidSignRequest(String),
}

/// Canonical felt-like hex string.
///
/// Values are normalized to `0x` followed by exactly 64 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FeltHex(String);

impl FeltHex {
    /// Parse and canonicalize a felt hex string.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let felt = Felt::from_hex(value).map_err(|e| DomainError::InvalidFeltHex(e.to_string()))?;
        Ok(Self(format!("0x{:064x}", felt)))
    }

    /// Convert a felt value to its canonical hex representation.
    pub fn from_felt(value: Felt) -> Self {
        Self(format!("0x{:064x}", value))
    }

    /// Return the canonical string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert back to a felt value.
    pub fn to_felt(&self) -> Felt {
        Felt::from_hex(&self.0).expect("FeltHex stores only validated values")
    }
}

impl fmt::Display for FeltHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for FeltHex {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<FeltHex> for String {
    fn from(value: FeltHex) -> Self {
        value.0
    }
}

/// Canonical lowercase hex bytes without a `0x` prefix.
///
/// Values are normalized to lowercase and must contain an even number of hex
/// digits so they round-trip exactly as bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HexBytes(String);

impl HexBytes {
    /// Parse and canonicalize a hex byte string.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let trimmed = value.trim();
        let normalized = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);

        if normalized.is_empty() {
            return Err(DomainError::InvalidHexBytes(
                "value must not be empty".to_string(),
            ));
        }

        if !normalized.len().is_multiple_of(2) {
            return Err(DomainError::InvalidHexBytes(
                "hex byte strings must have an even number of digits".to_string(),
            ));
        }

        if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidHexBytes(
                "value contains non-hex characters".to_string(),
            ));
        }

        Ok(Self(normalized.to_ascii_lowercase()))
    }

    /// Convert bytes to canonical lowercase hex.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(bytes))
    }

    /// Return the canonical lowercase hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decode into a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        hex::decode(&self.0).expect("HexBytes stores only validated values")
    }

    /// Decode into an exact-size array.
    pub fn to_array<const N: usize>(&self) -> Result<[u8; N], DomainError> {
        let bytes = self.to_vec();
        let actual_len = bytes.len();
        bytes.try_into().map_err(|_| {
            DomainError::InvalidHexBytes(format!("expected exactly {N} bytes, got {}", actual_len))
        })
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for HexBytes {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<HexBytes> for String {
    fn from(value: HexBytes) -> Self {
        value.0
    }
}

/// Stable identifier for a secret kept behind the trusted boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretRef(String);

impl SecretRef {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DomainError::EmptyField {
                field: "secret_ref",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretRef {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SecretRef> for String {
    fn from(value: SecretRef) -> Self {
        value.0
    }
}

/// Stable identifier for an operation tracked by a gateway.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(String);

impl OperationId {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DomainError::EmptyField {
                field: "operation_id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OperationId {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0
    }
}

/// Version tag for gateway/oracle protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const V1_0: Self = Self { major: 1, minor: 0 };
}

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
    },
    StarkRawMessage {
        secret: SecretRef,
        key_domain: StarkKeyDomain,
        derivation_path: DerivationPath,
        message: FeltHex,
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
                ..
            }
            | Self::StarkRawMessage {
                key_domain,
                derivation_path,
                ..
            } => {
                derivation_path.validate_for(key_domain.key_domain())?;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePolicy {
    pub ttl_ms: u64,
    pub stale_while_revalidate_ms: u64,
    pub max_entries: usize,
}

impl CachePolicy {
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

/// Machine-readable gateway/runtime failure codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayErrorCode {
    Undeployed,
    NotFound,
    ProviderTransport,
    InsufficientBalance,
    InsufficientFee,
    NonceMismatch,
    InvalidRequest,
    InvalidClassHash,
    ConstructorCalldataMismatch,
    InvalidDerivationPath,
    InvalidCachePolicy,
    InvalidWaitPolicy,
    UnsupportedKeyDomain,
    UnsupportedAccountClass,
    ChainMismatch,
    UnsupportedProtocolVersion,
    UnsupportedSigningDomain,
    CacheUnavailable,
    CacheStale,
    RpcDegraded,
    Timeout,
    SecretUnavailable,
    Internal,
}

/// Structured gateway/runtime error payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayError {
    pub code: GatewayErrorCode,
    pub retryable: bool,
    pub message: Option<String>,
}

impl GatewayError {
    pub fn new(
        code: GatewayErrorCode,
        retryable: bool,
        message: impl Into<Option<String>>,
    ) -> Self {
        Self {
            code,
            retryable,
            message: message.into(),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn felt_hex_normalizes_padding_and_case() {
        let short = FeltHex::parse("0xabc").unwrap();
        let padded = FeltHex::parse("0x0AbC").unwrap();

        assert_eq!(short, padded);
        assert_eq!(
            short.as_str(),
            "0x0000000000000000000000000000000000000000000000000000000000000abc"
        );
    }

    #[test]
    fn felt_hex_roundtrips_through_felt() {
        let original = Felt::from(42u64);
        let hex = FeltHex::from_felt(original);

        assert_eq!(hex.to_felt(), original);
    }

    #[test]
    fn hex_bytes_normalizes_prefix_and_case() {
        let bytes = HexBytes::parse("0xA0Bc").unwrap();

        assert_eq!(bytes.as_str(), "a0bc");
        assert_eq!(bytes.to_array::<2>().unwrap(), [0xa0, 0xbc]);
    }

    #[test]
    fn secret_ref_rejects_blank_values() {
        assert_eq!(
            SecretRef::new("   ").unwrap_err(),
            DomainError::EmptyField {
                field: "secret_ref"
            }
        );
    }

    #[test]
    fn cache_policy_requires_positive_ttl_and_capacity() {
        assert!(CachePolicy::new(0, 0, 10).is_err());
        assert!(CachePolicy::new(1_000, 0, 0).is_err());
        assert!(CachePolicy::new(1_000, 250, 64).is_ok());
    }

    #[test]
    fn wait_policy_requires_positive_interval_and_timeout() {
        assert!(WaitPolicy::new(0, 1_000).is_err());
        assert!(WaitPolicy::new(100, 0).is_err());
        assert!(WaitPolicy::new(250, 5_000).is_ok());
    }

    #[test]
    fn derivation_path_validates_coin_type_for_domain() {
        assert!(DerivationPath {
            coin_type: 9004,
            account_index: 0,
            address_index: 0,
        }
        .validate_for(KeyDomain::StarknetAccount)
        .is_ok());

        assert!(DerivationPath {
            coin_type: 5454,
            account_index: 0,
            address_index: 0,
        }
        .validate_for(KeyDomain::StarknetAccount)
        .is_err());
    }

    #[test]
    fn nostr_event_sign_request_requires_32_byte_event_id() {
        let request = SignRequest::NostrEvent {
            secret: SecretRef::new("nostr-secret").unwrap(),
            derivation_path: DerivationPath {
                coin_type: 1237,
                account_index: 0,
                address_index: 7,
            },
            event_id: HexBytes::parse(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
        };

        assert!(request.validate().is_ok());

        let invalid = SignRequest::NostrEvent {
            secret: SecretRef::new("nostr-secret").unwrap(),
            derivation_path: DerivationPath {
                coin_type: 1237,
                account_index: 0,
                address_index: 7,
            },
            event_id: HexBytes::parse("abcd").unwrap(),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn stark_hash_sign_request_requires_matching_coin_type() {
        let request = SignRequest::StarkHash {
            secret: SecretRef::new("stark-secret").unwrap(),
            key_domain: StarkKeyDomain::StarknetAccount,
            derivation_path: DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 1,
            },
            chain_id: ChainId::Sepolia,
            domain: StarkSignDomain::TransactionHash,
            hash: FeltHex::parse("0x1234").unwrap(),
        };

        assert!(request.validate().is_ok());

        let invalid = SignRequest::StarkHash {
            secret: SecretRef::new("stark-secret").unwrap(),
            key_domain: StarkKeyDomain::StarknetAccount,
            derivation_path: DerivationPath {
                coin_type: 5454,
                account_index: 0,
                address_index: 1,
            },
            chain_id: ChainId::Sepolia,
            domain: StarkSignDomain::TransactionHash,
            hash: FeltHex::parse("0x1234").unwrap(),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn raw_nostr_sign_request_accepts_utf8_or_hex_bytes() {
        let utf8_request = SignRequest::NostrRawMessage {
            secret: SecretRef::new("nostr-secret").unwrap(),
            derivation_path: DerivationPath {
                coin_type: 1237,
                account_index: 0,
                address_index: 7,
            },
            payload: RawMessagePayload::Utf8("hello nostr".to_string()),
        };
        assert!(utf8_request.validate().is_ok());

        let hex_request = SignRequest::NostrRawMessage {
            secret: SecretRef::new("nostr-secret").unwrap(),
            derivation_path: DerivationPath {
                coin_type: 1237,
                account_index: 0,
                address_index: 7,
            },
            payload: RawMessagePayload::Hex(HexBytes::parse("68656c6c6f").unwrap()),
        };
        assert!(hex_request.validate().is_ok());
    }

    #[test]
    fn operation_status_serializes_machine_shape() {
        let status = OperationStatus {
            id: OperationId::new("deploy-1").unwrap(),
            kind: OperationKind::DeployAccount,
            state: OperationState::Submitted {
                tx_hash: FeltHex::parse("0x123").unwrap(),
            },
            provenance: Some(Provenance {
                chain_id: ChainId::Sepolia,
                key_domain: KeyDomain::StarknetAccount,
                derivation_path: DerivationPath {
                    coin_type: 9004,
                    account_index: 0,
                    address_index: 0,
                },
                class_hash: Some(FeltHex::parse("0x456").unwrap()),
            }),
        };

        let json = serde_json::to_string(&status).unwrap();
        let roundtrip: OperationStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtrip, status);
        assert!(json.contains("\"Submitted\""));
        assert!(json.contains("\"DeployAccount\""));
    }

    #[test]
    fn account_snapshot_request_serializes_canonical_addresses() {
        let request = AccountSnapshotRequest {
            chain_id: ChainId::Sepolia,
            address: FeltHex::parse("0xabc").unwrap(),
            tokens: vec![TrackedToken {
                symbol: "STRK".into(),
                address: FeltHex::parse(
                    "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
                )
                .unwrap(),
                decimals: 18,
            }],
            block: BlockSelector::Latest,
            mode: QueryMode::ActiveView,
            cache_policy: CachePolicy::new(2_500, 500, 32).unwrap(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("0x0000000000000000000000000000000000000000000000000000000000000abc"));
    }
}
