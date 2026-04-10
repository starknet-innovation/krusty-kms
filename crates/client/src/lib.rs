//! Starknet wallet, deployment, and Tongo protocol client.

#[allow(dead_code)]
mod abi;
mod account;
mod address;
mod contract;
pub mod discovery;
#[allow(dead_code)]
mod erc20;
mod events;
mod operations;
mod provider;
mod serialization;
#[allow(dead_code)]
mod staking;
mod tx;
mod types;
mod wallet;

pub use account::Account;
pub use address::{pub_key_to_tongo_address, tongo_address_to_pub_key};
pub use contract::TongoContract;
pub use discovery::{check_account_deployed, discover_accounts, DiscoveredAccount};
pub use events::{
    BalanceDeclaredEvent, EventMetadata, FundEvent, OutsideFundEvent, RagequitEvent, RolloverEvent,
    TongoEvent, TransferDeclaredEvent, TransferEvent, WithdrawEvent,
};
pub use krusty_kms_common::{KmsError, Result};
pub use krusty_kms_wallet_api::{Tx, WaitOptions, WalletExecutor};
pub use operations::{
    build_erc20_approve, build_fund_calls, build_outside_fund_calls, build_ragequit_call,
    build_rollover_call, build_transfer_call, build_withdraw_call,
};
pub use provider::create_provider;
pub use tx::TxBuilder;
#[allow(deprecated)]
pub use types::{
    decrypt_cipher_balance_with_default_limit, decrypt_cipher_balance_with_limit,
    decrypt_cipher_balance_with_limit as decrypt_cipher_balance, erc20_to_tongo, tongo_to_erc20,
    AccountState, CipherBalance, DecryptedAccountState, DEFAULT_DECRYPT_SEARCH_LIMIT,
};
pub use wallet::deploy::{deploy_oz_account, estimate_deploy_fee, DeployResult};
pub use wallet::Wallet;
