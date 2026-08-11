//! Tongo protocol operations.
//!
//! This module provides the five core operations of the Tongo protocol:
//! - Fund: Deposit STRK into confidential balance
//! - Transfer: Send confidential STRK to another account
//! - Rollover: Activate pending balance
//! - Withdraw: Exit confidential balance to public STRK
//! - Ragequit: Emergency exit of all funds
//!
//! # Security Considerations
//!
//! All Tongo operations use zero-knowledge proofs to maintain privacy:
//!
//! - **Fund**: Creates encrypted balance with optional audit proof
//! - **Transfer**: Dual range proofs ensure no negative balances
//! - **Rollover**: Activates pending balance with signature proof
//! - **Withdraw**: Range proof ensures sufficient balance
//! - **Ragequit**: Exits full balance with Chaum-Pedersen proof
//!
//! ## Cryptographic Primitives
//!
//! - **ElGamal encryption**: Homomorphic encryption for confidential balances
//! - **Range proofs**: Bulletproofs-style proofs for value bounds
//! - **Audit proofs**: Optional regulatory compliance mechanism
//! - **Proof of Exponentiation (PoE)**: Proves knowledge of discrete log
//! - **Fiat-Shamir heuristic**: Non-interactive proof construction
//!
//! ## Timing Attack Resistance
//!
//! The scalar multiplication implementation uses double-and-add which is NOT
//! constant-time. For production deployments requiring resistance to timing
//! attacks, additional hardening may be required.
//!
//! ## Usage Example
//!
//! ```ignore
//! use krusty_kms_sdk::{TongoAccount, operations::{fund, FundParams}};
//! use krusty_kms_crypto::StarkCurve;
//! use starknet_types_core::felt::Felt;
//!
//! // Create account from private key
//! let account = TongoAccount::from_private_key(
//!     Felt::from(42u64),
//!     Felt::from(123456u64)
//! ).unwrap();
//!
//! // Create initial zero balance cipher
//! let g = StarkCurve::generator();
//! let current_balance = krusty_kms_common::ElGamalCiphertext { l: g.clone(), r: g };
//!
//! // Fund account
//! let fund_params = FundParams {
//!     amount: 1000,
//!     nonce: Felt::from(1u64),
//!     chain_id: Felt::from(0x534e5f5345504f4c4941u128),
//!     tongo_address: Felt::from(123456u64),
//!     sender_address: Felt::from(0u64),
//!     auditor_pub_key: None,
//!     current_balance,
//! };
//!
//! let fund_proof = fund(&account, fund_params).unwrap();
//! ```

mod fund;
mod ragequit;
mod rollover;
mod shared;
mod transfer;
mod withdraw;

pub use fund::fund;
pub use ragequit::ragequit;
pub use rollover::rollover;
pub use transfer::transfer;
pub use withdraw::withdraw;

use krusty_kms_common::{AuditProof, ElGamalCiphertext, ProofOfTransfer};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Fund operation parameters.
#[derive(Clone)]
pub struct FundParams {
    pub amount: u128,
    pub nonce: Felt,
    pub chain_id: Felt,
    pub tongo_address: Felt,
    pub sender_address: Felt,
    pub auditor_pub_key: Option<ProjectivePoint>,
    pub current_balance: ElGamalCiphertext,
}

/// Transfer operation parameters.
#[derive(Clone)]
pub struct TransferParams {
    /// The recipient's Tongo public key used to encrypt the transfer payload.
    pub recipient_public_key: ProjectivePoint,
    pub amount: u128,
    pub nonce: Felt,
    pub chain_id: Felt,
    pub tongo_address: Felt,
    pub sender_address: Felt,
    pub current_balance: ElGamalCiphertext,
    pub bit_size: usize,
    pub auditor_pub_key: Option<ProjectivePoint>,
}

/// Rollover operation parameters.
#[derive(Clone)]
pub struct RolloverParams {
    pub nonce: Felt,
    pub chain_id: Felt,
    pub tongo_address: Felt,
    pub sender_address: Felt,
}

/// Withdraw operation parameters.
#[derive(Clone)]
pub struct WithdrawParams {
    pub recipient_address: Felt,
    pub amount: u128,
    pub nonce: Felt,
    pub chain_id: Felt,
    pub tongo_address: Felt,
    pub sender_address: Felt,
    pub current_balance: ElGamalCiphertext,
    pub bit_size: usize,
    pub auditor_key: Option<ProjectivePoint>,
}

/// Ragequit operation parameters.
#[derive(Clone)]
pub struct RagequitParams {
    pub recipient_address: Felt,
    pub nonce: Felt,
    pub chain_id: Felt,
    pub tongo_address: Felt,
    pub sender_address: Felt,
    pub current_balance: ElGamalCiphertext,
    pub auditor_key: Option<ProjectivePoint>,
}

// Proof structures

/// Audit information for declaring balance.
#[derive(Clone)]
pub struct Audit {
    pub audited_balance: ElGamalCiphertext,
    pub hint_ciphertext: [u8; 64],
    pub hint_nonce: [u8; 24],
    pub proof: AuditProof,
}

pub struct FundProof {
    pub y: ProjectivePoint,
    pub proof: krusty_kms_common::PoeProof,
    pub amount: u128,
    pub audit: Option<Audit>,
}

pub struct TransferProof {
    pub transfer_balance_l: ProjectivePoint, // transferBalance.L (for recipient)
    pub transfer_balance_r: ProjectivePoint, // transferBalance.R (for recipient)
    pub transfer_balance_self_l: ProjectivePoint, // transferBalanceSelf.L (for sender)
    pub transfer_balance_self_r: ProjectivePoint, // transferBalanceSelf.R (for sender)
    pub proof: ProofOfTransfer, // Complete transfer proof with 8 commitments, 5 scalars, 2 range proofs
    pub auxiliar_cipher: ElGamalCiphertext, // (V = g^b*h^r, R_aux = g^r)
    pub auxiliar_cipher2: ElGamalCiphertext, // (V2 = g^b_left*h^r2, R_aux2 = g^r2)
    pub new_balance_cipher: ElGamalCiphertext, // Updated balance cipher after transfer
    pub audit_balance: Option<Audit>, // Sender's balance after transfer (optional)
    pub audit_transfer: Option<Audit>, // Transfer cipher audit (optional)
}

pub struct RolloverProof {
    pub y: ProjectivePoint,
    pub proof: krusty_kms_common::PoeProof,
    pub pending_amount: u128,
}

pub struct WithdrawProof {
    pub y: ProjectivePoint,                 // User's public key
    pub a_x: ProjectivePoint,               // Commitment for proof of private key
    pub a_r: ProjectivePoint,               // Commitment for range proof randomness
    pub a: ProjectivePoint,                 // Commitment for balance encryption proof
    pub a_v: ProjectivePoint,               // Commitment for V linkage proof
    pub sx: Felt,                           // Response for private key
    pub sb: Felt,                           // Response for leftover balance
    pub sr: Felt,                           // Response for range proof randomness
    pub auxiliar_cipher: ElGamalCiphertext, // (V = g^b_left*h^r, R_aux = g^r)
    pub range: krusty_kms_common::Range,    // Range proof for leftover balance
    pub amount: u128,
    pub recipient: Felt,
    pub audit: Option<Audit>, // Optional audit proof for leftover balance
}

pub struct RagequitProof {
    pub y: ProjectivePoint,   // User's public key
    pub a_x: ProjectivePoint, // Ax = g^kx
    pub a_r: ProjectivePoint, // AR = R0^kx
    pub sx: Felt,             // sx = kx + c*x
    pub amount: u128,         // Full balance amount to withdraw
    pub recipient: Felt,      // Recipient address
    pub audit: Option<Audit>, // Optional audit proof (for consistency)
}

#[cfg(test)]
mod tests;
