//! TONGO SDK - Confidential Transactions on Starknet.
//!
//! This SDK provides high-level APIs for interacting with the TONGO protocol:
//! - Account management
//! - Fund operations (deposit to confidential balance)
//! - Transfer operations (confidential transfers)
//! - Rollover operations (activate pending balance)
//! - Withdraw operations (exit to public balance)
//!
//! # Dual-Key Model (Owner + View)
//!
//! For improved wallet security, this SDK supports a dual-key model where
//! two keys are derived from different BIP-44 coin types:
//! - Ownership/Spending key: coin type 5454 (authorizes operations and proofs)
//! - Viewing/Decryption key: coin type 5353 (decrypts balances/memos only)
//!
//! Contracts remain unchanged; all on-chain proofs continue to use the
//! ownership key. For transfers, pass the recipient's viewing public key in
//! `TransferParams::recipient_public_key` to allow recipients to decrypt
//! without exposing their spending key.

pub mod account;
pub mod crypto;
pub mod operations;

pub use account::TongoAccount;
pub use crypto::{decrypt_as_auditor, encrypt_for_auditor};
pub use operations::{fund, ragequit, rollover, transfer, withdraw};

/// Re-export common types
pub use krusty_kms_common::*;
pub use krusty_kms::*;
pub use krusty_kms_crypto::*;
