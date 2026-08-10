//! Versioned stdio oracle transport on top of the gateway surface.
//!
//! Inputs:
//! - newline-delimited JSON requests matching `krusty-kms-domain` oracle types
//! - an `OracleHandler` implementation, typically `krusty-kms-gateway::Gateway`
//!
//! Outputs:
//! - one newline-delimited JSON response per non-empty request line
//! - typed protocol errors for malformed requests, unsupported versions, and gateway failures
//!
//! Invariants:
//! - responses always use the server protocol version
//! - parse failures never panic and return `id: null`
//! - transport does not own secrets, caches, or RPC state; it delegates to the handler

#![forbid(unsafe_code)]

mod handler;
mod line_reader;
mod stdio;

#[cfg(test)]
mod tests;

pub use handler::OracleHandler;
pub use stdio::StdioOracle;
