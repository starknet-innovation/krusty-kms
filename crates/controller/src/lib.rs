//! Cartridge Controller wallet integration for krusty-kms.
//!
//! Provides [`ControllerWallet`] — a [`WalletExecutor`](krusty_kms_client::WalletExecutor)
//! backed by the Cartridge `account_sdk`, offering session-based signing,
//! paymaster-sponsored gas, and Cartridge identity.
//!
//! This crate is separated from `krusty-kms-client` because `account_sdk`
//! is only available as a git dependency and cannot be published to crates.io.

mod convert;
mod error;
mod policy;
mod wallet;

pub use policy::{erc20_policies, staking_policies, FeeMode, SessionPolicy};
pub use wallet::ControllerWallet;
