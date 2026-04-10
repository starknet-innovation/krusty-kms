//! Tongo confidential account and proof-operation flows.
//!
//! This crate intentionally exposes only Tongo-specific account and proof
//! generation behavior. Lower-level derivation, signing, and reusable value
//! types live in `krusty-kms`, `krusty-kms-crypto`, and `krusty-kms-common`.

pub mod account;
pub mod crypto;
pub mod operations;
pub mod serialization;

pub use account::TongoAccount;
pub use crypto::{decrypt_as_auditor, encrypt_for_auditor};
pub use operations::{
    fund, ragequit, rollover, transfer, withdraw, Audit, FundParams, FundProof, RagequitParams,
    RagequitProof, RolloverParams, RolloverProof, TransferParams, TransferProof, WithdrawParams,
    WithdrawProof,
};
