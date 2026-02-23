//! Error mapping from `account_sdk::errors::ControllerError` to `KmsError`.

use account_sdk::errors::ControllerError;
use krusty_kms_common::KmsError;

/// Convert a `ControllerError` into a `KmsError`.
pub fn controller_error_to_kms(err: ControllerError) -> KmsError {
    match err {
        ControllerError::NotDeployed { .. } => {
            KmsError::AccountNotDeployed("Controller account not deployed".into())
        }
        ControllerError::InsufficientBalance {
            fee_estimate,
            balance,
        } => KmsError::FeeEstimationFailed(format!(
            "Insufficient balance: need {} but have {}",
            fee_estimate.overall_fee, balance
        )),
        ControllerError::TransactionReverted(msg) => KmsError::TransactionReverted(msg),
        ControllerError::TransactionTimeout => {
            KmsError::Timeout("Controller transaction timed out".into())
        }
        ControllerError::PaymasterError(e) => {
            KmsError::ControllerError(format!("Paymaster error: {e}"))
        }
        ControllerError::PaymasterNotSupported => {
            KmsError::ControllerError("Paymaster not supported on this chain".into())
        }
        ControllerError::SessionRefreshRequired => {
            KmsError::ControllerError("Session expired, refresh required".into())
        }
        ControllerError::AccountError(e) => {
            KmsError::TransactionError(format!("Account error: {e}"))
        }
        ControllerError::ProviderError(e) => KmsError::RpcError(e.to_string()),
        other => KmsError::ControllerError(other.to_string()),
    }
}
