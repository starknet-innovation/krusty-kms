//! Starknet client for interacting with TONGO contracts and the wider Starknet ecosystem.
//!
//! This crate provides utilities and clients for deploying and interacting
//! with TONGO contracts on Starknet using the starknet-rs SDK, as well as
//! higher-level abstractions for wallets, ERC-20 tokens, staking, and
//! transaction batching.

pub mod abi;
pub mod account;
pub mod address;
pub mod contract;
pub mod erc20;
pub mod events;
pub mod operations;
pub mod provider;
pub mod serialization;
pub mod staking;
pub mod tx;
pub mod types;
pub mod wallet;

pub use account::Account;
pub use address::{pub_key_to_tongo_address, tongo_address_to_pub_key};
pub use contract::TongoContract;
pub use erc20::Erc20;
pub use events::TongoEventReader;
pub use krusty_kms_common::{KmsError, Result};
pub use operations::{
    build_erc20_approve, build_fund_calls, build_outside_fund_calls, build_ragequit_call,
    build_rollover_call, build_transfer_call, build_withdraw_call,
};
pub use provider::create_provider;
pub use staking::{PoolPosition, Staking};
pub use starknet_rust;
pub use tx::{Tx, TxBuilder};
pub use types::{
    decrypt_cipher_balance, erc20_to_tongo, tongo_to_erc20, AccountState, CipherBalance,
    DecryptedAccountState,
};
pub use wallet::deploy::{deploy_oz_account, estimate_deploy_fee, DeployResult};
pub use wallet::{Wallet, WalletExecutor};
