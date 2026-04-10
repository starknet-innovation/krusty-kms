//! Wallet utility functions for Felt conversion and deployment checking.

use krusty_kms_common::{is_already_deployed_validation_failure, KmsError, Result};
use starknet_rust::accounts::AccountFactoryError;
use starknet_rust::core::types::StarknetError;
use starknet_rust::core::types::{BlockId, BlockTag};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::{Provider, ProviderError};
use std::sync::Arc;

/// Type alias for starknet-rs Felt.
pub type StarknetRsFelt = starknet_rust::core::types::Felt;
/// Type alias for starknet-types-core Felt.
pub type CoreFelt = starknet_types_core::felt::Felt;

/// Convert from starknet-types-core Felt to starknet-rs Felt.
#[inline]
pub fn core_felt_to_rs(felt: CoreFelt) -> StarknetRsFelt {
    StarknetRsFelt::from_bytes_be(&felt.to_bytes_be())
}

/// Convert from starknet-rs Felt to starknet-types-core Felt.
#[inline]
pub fn rs_felt_to_core(felt: StarknetRsFelt) -> CoreFelt {
    CoreFelt::from_bytes_be(&felt.to_bytes_be())
}

/// Check whether a contract is deployed at the given address.
///
/// Queries `getClassHashAt` — if the call succeeds, the address is deployed.
pub async fn check_deployed(
    provider: &Arc<JsonRpcClient<HttpTransport>>,
    address: StarknetRsFelt,
) -> Result<bool> {
    match provider
        .get_class_hash_at(BlockId::Tag(BlockTag::Latest), address)
        .await
    {
        Ok(_) => Ok(true),
        Err(error) if is_contract_not_found(&error) => Ok(false),
        Err(error) => Err(KmsError::RpcError(error.to_string())),
    }
}

pub(crate) fn map_deploy_factory_error<S: std::fmt::Display>(
    error: AccountFactoryError<S>,
) -> KmsError {
    match error {
        AccountFactoryError::Provider(error) => map_deploy_provider_error(error),
        AccountFactoryError::Signing(error) => KmsError::CryptoError(error.to_string()),
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
        StarknetError::ContractNotFound => KmsError::ContractNotFound(error.to_string()),
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

fn is_contract_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::ContractNotFound)
    )
}

#[allow(dead_code)]
pub(crate) fn is_entrypoint_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::EntrypointNotFound)
    )
}

/// Extract a `u16` from the low 2 bytes of a starknet-rs Felt.
pub(crate) fn felt_to_u16(felt: &StarknetRsFelt) -> u16 {
    let bytes = felt.to_bytes_be();
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[30..32]);
    u16::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_felt_roundtrip() {
        let core = CoreFelt::from(0xDEADBEEFu64);
        let rs = core_felt_to_rs(core);
        let back = rs_felt_to_core(rs);
        assert_eq!(core, back);
    }

    #[test]
    fn test_felt_zero() {
        let core = CoreFelt::ZERO;
        let rs = core_felt_to_rs(core);
        assert_eq!(rs, StarknetRsFelt::ZERO);
    }

    #[test]
    fn test_contract_not_found_provider_error_is_treated_as_undeployed() {
        assert!(is_contract_not_found(&ProviderError::StarknetError(
            StarknetError::ContractNotFound,
        )));
        assert!(!is_contract_not_found(&ProviderError::RateLimited));
    }

    #[test]
    fn test_entrypoint_not_found_provider_error_is_treated_as_selector_mismatch() {
        assert!(is_entrypoint_not_found(&ProviderError::StarknetError(
            StarknetError::EntrypointNotFound,
        )));
        assert!(!is_entrypoint_not_found(&ProviderError::RateLimited));
    }

    #[test]
    fn test_deploy_error_maps_typed_class_hash_failure() {
        let error = map_deploy_factory_error(AccountFactoryError::<&str>::Provider(
            ProviderError::StarknetError(StarknetError::ClassHashNotFound),
        ));
        assert!(matches!(error, KmsError::InvalidClassHash(_)));
    }

    #[test]
    fn test_deploy_error_maps_typed_fee_failure() {
        let error = map_deploy_factory_error(AccountFactoryError::<&str>::Provider(
            ProviderError::StarknetError(StarknetError::InsufficientAccountBalance),
        ));
        assert!(matches!(error, KmsError::InsufficientFeeBalance(_)));
    }

    #[test]
    fn test_deploy_error_recognizes_already_deployed_validation_failure() {
        let error = map_deploy_factory_error(AccountFactoryError::<&str>::Provider(
            ProviderError::StarknetError(StarknetError::ValidationFailure(
                "Requested ContractAddress has already been deployed".to_string(),
            )),
        ));
        assert!(matches!(error, KmsError::AlreadyDeployed(_)));
    }
}
