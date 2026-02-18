//! Common types and utilities for TONGO protocol implementation.
//!
//! This crate provides shared functionality used across all TONGO crates:
//! - Type conversions between different numeric representations
//! - Field element operations
//! - Serialization/deserialization helpers
//! - Error types

pub mod error;
pub mod types;
pub mod utils;

pub use error::{GhoulError, Result};
pub use types::*;
