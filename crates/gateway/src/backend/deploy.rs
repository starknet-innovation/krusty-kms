//! Deploy-path support: typed error mapping for account-factory submissions,
//! OpenZeppelin descriptor validation, and fee-ceiling admission.

use super::rpc::map_provider_error;
use crate::{map_kms_error, GatewayResult};
use krusty_kms_common::fee::ResourceBoundsCeiling;
use krusty_kms_common::{is_already_deployed_validation_failure, KmsError};
use krusty_kms_domain::{AccountDescriptor, FeltHex, GatewayError, GatewayErrorCode};
use starknet_rust::accounts::{AccountDeploymentV3, AccountFactoryError};
use starknet_rust::core::types::{FeeEstimate, StarknetError};
use starknet_rust::providers::ProviderError;
use starknet_types_core::felt::Felt as CoreFelt;

pub(super) fn map_deploy_submission_error<S: std::fmt::Display>(
    error: AccountFactoryError<S>,
) -> GatewayError {
    match error {
        AccountFactoryError::Provider(error) => map_deploy_provider_error(error),
        AccountFactoryError::Signing(error) => {
            map_kms_error(KmsError::CryptoError(error.to_string()))
        }
        AccountFactoryError::FeeOutOfRange => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some("fee calculation overflow".to_string()),
        ),
    }
}

pub(super) fn map_deploy_provider_error(error: ProviderError) -> GatewayError {
    match error {
        ProviderError::StarknetError(error) => map_deploy_starknet_error(error),
        other => map_provider_error(other),
    }
}

pub(super) fn map_deploy_starknet_error(error: StarknetError) -> GatewayError {
    match error {
        StarknetError::ClassHashNotFound => {
            map_kms_error(KmsError::InvalidClassHash("ClassHashNotFound".to_string()))
        }
        StarknetError::ContractNotFound => {
            map_kms_error(KmsError::ContractNotFound("ContractNotFound".to_string()))
        }
        StarknetError::InsufficientAccountBalance
        | StarknetError::InsufficientResourcesForValidate => {
            map_kms_error(KmsError::InsufficientFeeBalance(error.to_string()))
        }
        StarknetError::ValidationFailure(message) => {
            map_deploy_textual_starknet_error(message, GatewayErrorCode::InvalidRequest, false)
        }
        StarknetError::UnexpectedError(message) => {
            map_deploy_textual_starknet_error(message, GatewayErrorCode::RpcDegraded, true)
        }
        other => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(other.to_string()),
        ),
    }
}

fn map_deploy_textual_starknet_error(
    message: String,
    fallback_code: GatewayErrorCode,
    retryable: bool,
) -> GatewayError {
    if indicates_already_deployed(&message) {
        map_kms_error(KmsError::AlreadyDeployed(message))
    } else {
        GatewayError::new(fallback_code, retryable, Some(message))
    }
}

/// `derived_public_key` is the Stark public key of the private key the caller
/// intends to deploy with; deriving it is the caller's job so no signing-key
/// object needs to exist here.
pub(super) fn validate_open_zeppelin_descriptor(
    account: &AccountDescriptor,
    derived_public_key: CoreFelt,
) -> GatewayResult<()> {
    if account.public_key.to_felt() != derived_public_key {
        return Err(GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(
                "account descriptor public key does not match the provided private key".to_string(),
            ),
        ));
    }

    let expected_calldata = [account.public_key.to_felt()];
    let actual_calldata: Vec<_> = account
        .constructor_calldata
        .iter()
        .map(FeltHex::to_felt)
        .collect();
    if actual_calldata != expected_calldata {
        return Err(GatewayError::new(
            GatewayErrorCode::ConstructorCalldataMismatch,
            false,
            Some(
                "OpenZeppelin deploy descriptor must use constructor calldata [public_key]"
                    .to_string(),
            ),
        ));
    }

    if account.deployer_address.to_felt() != CoreFelt::ZERO {
        return Err(GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some("OpenZeppelin deploy descriptor must use deployer_address = 0x0".to_string()),
        ));
    }

    Ok(())
}

fn indicates_already_deployed(message: &str) -> bool {
    is_already_deployed_validation_failure(message)
}

/// Scale `estimate` exactly as `starknet-rs` would, admit it against `ceiling`,
/// and pin the admitted bounds on `deployment`.
///
/// Rejections are non-retryable: the estimate came from the untrusted RPC, so
/// retrying against the same endpoint cannot make it admissible.
pub(super) fn bound_deployment<'f, F>(
    deployment: AccountDeploymentV3<'f, F>,
    estimate: &FeeEstimate,
    ceiling: &ResourceBoundsCeiling,
) -> GatewayResult<AccountDeploymentV3<'f, F>> {
    let bounds = ceiling
        .admit_estimate(
            (estimate.l1_gas_consumed, estimate.l1_gas_price),
            (estimate.l2_gas_consumed, estimate.l2_gas_price),
            (estimate.l1_data_gas_consumed, estimate.l1_data_gas_price),
        )
        .map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::InvalidRequest,
                false,
                Some(format!("fee ceiling: {error}")),
            )
        })?;
    Ok(deployment
        .l1_gas(bounds.l1_gas.max_amount)
        .l1_gas_price(bounds.l1_gas.max_price_per_unit)
        .l2_gas(bounds.l2_gas.max_amount)
        .l2_gas_price(bounds.l2_gas.max_price_per_unit)
        .l1_data_gas(bounds.l1_data_gas.max_amount)
        .l1_data_gas_price(bounds.l1_data_gas.max_price_per_unit))
}
