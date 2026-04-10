//! Error mapping from `account_sdk::errors::ControllerError` to `KmsError`.

use account_sdk::errors::ControllerError;
use account_sdk::signers::SignError;
use krusty_kms_common::{is_already_deployed_validation_failure, KmsError};
use starknet::accounts::AccountFactoryError;
use starknet::core::types::StarknetError;
use starknet::providers::ProviderError;

/// Convert a `ControllerError` into a `KmsError`.
pub fn controller_error_to_kms(err: ControllerError) -> KmsError {
    match err {
        ControllerError::NotDeployed { .. } => {
            KmsError::AccountNotDeployed("Controller account not deployed".into())
        }
        ControllerError::AccountFactoryError(error) => map_account_factory_error(error),
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

fn map_account_factory_error(error: AccountFactoryError<SignError>) -> KmsError {
    match error {
        AccountFactoryError::Provider(error) => map_deploy_provider_error(error),
        AccountFactoryError::Signing(error) => KmsError::ControllerError(error.to_string()),
        AccountFactoryError::FeeOutOfRange => {
            KmsError::TransactionError("fee calculation overflow".to_string())
        }
    }
}

fn map_deploy_provider_error(error: ProviderError) -> KmsError {
    match error {
        ProviderError::StarknetError(error) => map_deploy_starknet_error(error),
        other => KmsError::RpcError(other.to_string()),
    }
}

fn map_deploy_starknet_error(error: StarknetError) -> KmsError {
    match error {
        StarknetError::ClassHashNotFound => KmsError::InvalidClassHash(error.to_string()),
        StarknetError::ContractNotFound => KmsError::AccountNotDeployed(error.to_string()),
        StarknetError::InsufficientAccountBalance
        | StarknetError::InsufficientResourcesForValidate => {
            KmsError::InsufficientFeeBalance(error.to_string())
        }
        StarknetError::ValidationFailure(message) => {
            if is_already_deployed_validation_failure(&message) {
                KmsError::AlreadyDeployed(message)
            } else {
                KmsError::TransactionError(message)
            }
        }
        StarknetError::UnexpectedError(message) => KmsError::RpcError(message),
        other => KmsError::TransactionError(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_factory_error_maps_typed_class_hash_failure() {
        let error =
            controller_error_to_kms(ControllerError::AccountFactoryError(AccountFactoryError::<
                SignError,
            >::Provider(
                ProviderError::StarknetError(StarknetError::ClassHashNotFound),
            )));

        assert!(matches!(error, KmsError::InvalidClassHash(_)));
    }

    #[test]
    fn account_factory_error_maps_typed_fee_failure() {
        let error =
            controller_error_to_kms(ControllerError::AccountFactoryError(AccountFactoryError::<
                SignError,
            >::Provider(
                ProviderError::StarknetError(StarknetError::InsufficientAccountBalance),
            )));

        assert!(matches!(error, KmsError::InsufficientFeeBalance(_)));
    }

    #[test]
    fn account_factory_error_recognizes_already_deployed_validation_failure() {
        let error =
            controller_error_to_kms(ControllerError::AccountFactoryError(AccountFactoryError::<
                SignError,
            >::Provider(
                ProviderError::StarknetError(StarknetError::ValidationFailure(
                    "Requested ContractAddress has already been deployed".to_string(),
                )),
            )));

        assert!(matches!(error, KmsError::AlreadyDeployed(_)));
    }
}
