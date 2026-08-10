//! Effectful Starknet backend boundary for the gateway runtime.
//!
//! [`GatewayBackend`] isolates RPC and deployment effects behind a replaceable
//! trait; [`StarknetGatewayBackend`] is the default JSON-RPC implementation.

mod deploy;
mod interface;
mod rpc;
mod starknet;
mod wait;

#[cfg(test)]
mod tests;

pub(crate) type StarknetRsFelt = starknet_rust::core::types::Felt;

pub use interface::{DeployExecution, GatewayBackend};
pub use starknet::StarknetGatewayBackend;
