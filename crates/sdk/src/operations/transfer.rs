use super::{transfer_state::TransferBuildState, TransferParams, TransferProof};
use crate::{crypto::validate_hint_context, TongoAccount};
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
    krusty_kms_crypto::range::validate_bit_size(params.bit_size)?;
    if params.auditor_pub_key.is_some()
        && params.amount != 0
        && account.has_sufficient_balance(params.amount)
    {
        validate_hint_context(params.amount, &params.nonce)?;
        validate_hint_context(account.balance() - params.amount, &params.nonce)?;
    }
    TransferBuildState::new(account, params)?.execute()
}
