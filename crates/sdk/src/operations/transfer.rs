use super::{transfer_state::TransferBuildState, TransferParams, TransferProof};
use crate::TongoAccount;
use krusty_kms_common::Result;

/// Execute a transfer operation.
///
/// The protocol phases live in TransferBuildState so validation, ciphertext
/// construction, range proofs, the Fiat-Shamir proof, and optional audits can
/// be reviewed independently.
///
/// # Errors
///
/// Returns KmsError when validation, point conversion, range-proof generation,
/// scalar arithmetic, or optional audit generation fails.
pub fn transfer(account: &TongoAccount, params: TransferParams) -> Result<TransferProof> {
    TransferBuildState::new(account, params)?.execute()
}
