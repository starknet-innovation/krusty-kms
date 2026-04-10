//! Cartridge Controller wallet integration for krusty-kms.
//!
//! Provides [`ControllerWallet`] backed by the Cartridge `account_sdk`,
//! offering session-based signing, paymaster-sponsored gas, and Cartridge
//! identity over the shared `krusty-kms-wallet-api` execution boundary.
//!
//! This crate is separated from `krusty-kms-client` because `account_sdk`
//! is only available as a git dependency and cannot be published to crates.io.

mod convert;
mod error;
mod policy;
mod tx_builder;
mod wallet;

pub use krusty_kms_wallet_api::{Tx, WaitOptions, WalletExecutor};
pub use policy::{erc20_policies, staking_policies, FeeMode, SessionPolicy};
pub use tx_builder::TxBuilder;
pub use wallet::ControllerWallet;
