//! Starknet client for interacting with TONGO contracts and the wider Starknet ecosystem.
//!
//! This crate provides utilities and clients for deploying and interacting
//! with TONGO contracts on Starknet using the starknet-rs SDK, as well as
//! higher-level abstractions for wallets, ERC-20 tokens, staking, and
//! transaction batching.

pub mod abi;
pub mod contract;
pub mod erc20;
pub mod operations;
pub mod provider;
pub mod serialization;
pub mod staking;
pub mod tx;
pub mod types;
pub mod wallet;

pub use contract::TongoContract;
pub use erc20::Erc20;
pub use krusty_kms_common::{KmsError, Result};
pub use operations::{build_erc20_approve, build_fund_calls, build_rollover_call, build_transfer_call, build_withdraw_call, build_ragequit_call};
pub use provider::create_provider;
pub use staking::{Staking, PoolPosition};
pub use starknet_rust;
pub use tx::{Tx, TxBuilder};
pub use types::{AccountState, CipherBalance, DecryptedAccountState, decrypt_cipher_balance};
pub use wallet::Wallet;
