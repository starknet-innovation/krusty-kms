//! Pure integration-domain contracts for TUI and gateway integrations.
//!
//! This crate intentionally contains no networking, clocks, filesystem access,
//! async runtime, or global mutable state. It exists to stabilize the typed
//! request/result/error surface that higher-level adapters and transports can
//! build on without re-inventing protocol glue.

pub mod oracle;

mod account;
mod error;
mod primitives;
mod runtime;
mod signing;

#[cfg(test)]
mod tests;

pub use oracle::{
    GetOperationStatusRequest, OperationLookupResult, OracleCommand, OracleCommandName,
    OracleOutcome, OracleRequest, OracleResponse, OracleResult, ProtocolInfo, RequestId,
    TrackedCommandResult,
};

pub use account::{
    AccountClassKind, AccountClassSpec, AccountDescriptor, CheckDeploymentResult, DeploymentState,
    DerivationPath, DerivationRequest, KeyDomain, Provenance, SaltPolicySpec,
};
pub use error::{DomainError, GatewayError, GatewayErrorCode};
pub use primitives::{FeltHex, HexBytes, OperationId, ProtocolVersion, SecretRef};
pub use runtime::{
    AccountSnapshot, AccountSnapshotRequest, BlockSelector, CacheMetadata, CachePolicy,
    CacheStatus, DeployAccountRequest, DeployAccountResult, DeployMode, OperationKind,
    OperationState, OperationStatus, QueryMode, SnapshotBlockMetadata, TokenBalanceSnapshot,
    TrackedToken, WaitPolicy,
};
pub use signing::{
    RawMessagePayload, SignRequest, SignResult, StarkKeyDomain, StarkSignDomain,
};
