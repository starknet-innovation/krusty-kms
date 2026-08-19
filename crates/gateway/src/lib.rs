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

#![forbid(unsafe_code)]

mod account_class;
mod accounts;
mod backend;
mod clock;
mod errors;
mod gateway;
mod operations;
mod signing;
mod snapshot;
mod snapshot_cache;
mod types;

#[cfg(test)]
mod tests;

pub use backend::{DeployExecution, GatewayBackend, StarknetGatewayBackend};
pub use clock::{Clock, SystemClock};
pub use gateway::Gateway;
// Re-exported so `StarknetGatewayBackend::with_fee_bounds` is callable without
// taking a direct dependency on krusty-kms-common.
pub use krusty_kms_common::fee::{FeeBounds, ONE_STRK_FRI};
pub use types::{
    GatewayResponse, GatewayResult, OperationRetentionError, OperationRetentionPolicy,
    SecretResolver,
};

pub(crate) use errors::map_kms_error;
