//! Starknet client for interacting with TONGO contracts.
//!
//! This crate provides utilities and clients for deploying and interacting
//! with TONGO contracts on Starknet using the starknet-rs SDK.

pub mod contract;
pub mod operations;
pub mod provider;
pub mod serialization;
pub mod types;

pub use contract::TongoContract;
pub use krusty_kms_common::{KmsError, Result};
pub use operations::{build_erc20_approve, build_fund_calls, build_rollover_call, build_transfer_call, build_withdraw_call, build_ragequit_call};
pub use provider::create_provider;
pub use starknet;
pub use types::{AccountState, CipherBalance, DecryptedAccountState, decrypt_cipher_balance};
