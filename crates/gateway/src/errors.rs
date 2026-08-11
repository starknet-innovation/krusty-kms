//! Mapping from KMS/domain errors to typed gateway errors.

use krusty_kms_common::KmsError;
use krusty_kms_domain::{DomainError, GatewayError, GatewayErrorCode};

pub(crate) fn map_kms_error(error: KmsError) -> GatewayError {
    match error {
        KmsError::AccountNotDeployed(message) => {
            GatewayError::new(GatewayErrorCode::Undeployed, false, Some(message))
        }
        KmsError::ContractNotFound(message) => {
            GatewayError::new(GatewayErrorCode::NotFound, false, Some(message))
        }
        // Amounts intentionally omitted: the available balance is confidential.
        KmsError::InsufficientBalance => GatewayError::new(
            GatewayErrorCode::InsufficientBalance,
            false,
            Some("insufficient balance for requested amount".to_string()),
        ),
        KmsError::InsufficientFeeBalance(message) => {
            GatewayError::new(GatewayErrorCode::InsufficientFee, false, Some(message))
        }
        KmsError::InvalidClassHash(message) => {
            GatewayError::new(GatewayErrorCode::InvalidClassHash, false, Some(message))
        }
        KmsError::InvalidDerivationPath(message) => GatewayError::new(
            GatewayErrorCode::InvalidDerivationPath,
            false,
            Some(message),
        ),
        KmsError::Timeout(message) => {
            GatewayError::new(GatewayErrorCode::Timeout, true, Some(message))
        }
        KmsError::InvalidMnemonic(message) | KmsError::InvalidPrivateKey(message) => {
            GatewayError::new(GatewayErrorCode::SecretUnavailable, false, Some(message))
        }
        KmsError::RpcError(message) | KmsError::FeeEstimationFailed(message) => {
            GatewayError::new(GatewayErrorCode::ProviderTransport, true, Some(message))
        }
        KmsError::TransactionError(message) => classify_transaction_error(message),
        KmsError::TransactionReverted(message) => classify_reverted_transaction_error(message),
        KmsError::AlreadyDeployed(message) => {
            GatewayError::new(GatewayErrorCode::InvalidRequest, false, Some(message))
        }
        KmsError::InvalidPublicKey(message)
        | KmsError::CryptoError(message)
        | KmsError::SerializationError(message)
        | KmsError::DeserializationError(message)
        | KmsError::InvalidAmount(message)
        | KmsError::StarknetCryptoError(message)
        | KmsError::InvalidProof(message)
        | KmsError::StakingError(message)
        | KmsError::MultisigError(message)
        | KmsError::ControllerError(message) => {
            GatewayError::new(GatewayErrorCode::InvalidRequest, false, Some(message))
        }
        KmsError::HexError(error) => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(error.to_string()),
        ),
        KmsError::JsonError(error) => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(error.to_string()),
        ),
        KmsError::PointAtInfinity => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some("derived public key is point at infinity".to_string()),
        ),
    }
}

pub(crate) fn map_domain_error(error: DomainError) -> GatewayError {
    match error {
        DomainError::InvalidDerivationPath(message) => GatewayError::new(
            GatewayErrorCode::InvalidDerivationPath,
            false,
            Some(message),
        ),
        DomainError::InvalidCachePolicy(message) => GatewayError::new(
            GatewayErrorCode::InvalidCachePolicy,
            false,
            Some(message.to_string()),
        ),
        DomainError::InvalidWaitPolicy(message) => GatewayError::new(
            GatewayErrorCode::InvalidWaitPolicy,
            false,
            Some(message.to_string()),
        ),
        DomainError::InvalidFeltHex(message) => {
            GatewayError::new(GatewayErrorCode::InvalidRequest, false, Some(message))
        }
        DomainError::InvalidHexBytes(message)
        | DomainError::InvalidSignRequest(message)
        | DomainError::InvalidSecretRef(message) => {
            GatewayError::new(GatewayErrorCode::InvalidRequest, false, Some(message))
        }
        DomainError::EmptyField { field } => GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(format!("field {} must not be empty", field)),
        ),
    }
}

fn classify_transaction_error(message: String) -> GatewayError {
    let lower = message.to_lowercase();
    let code = if lower.contains("nonce") {
        GatewayErrorCode::NonceMismatch
    } else if lower.contains("constructor") || lower.contains("calldata") {
        GatewayErrorCode::ConstructorCalldataMismatch
    } else if lower.contains("class hash") {
        GatewayErrorCode::InvalidClassHash
    } else {
        GatewayErrorCode::RpcDegraded
    };

    let retryable = matches!(
        code,
        GatewayErrorCode::NonceMismatch | GatewayErrorCode::RpcDegraded
    );

    GatewayError::new(code, retryable, Some(message))
}

fn classify_reverted_transaction_error(message: String) -> GatewayError {
    let lower = message.to_lowercase();
    let code = if lower.contains("constructor") || lower.contains("calldata") {
        GatewayErrorCode::ConstructorCalldataMismatch
    } else if lower.contains("class hash") {
        GatewayErrorCode::InvalidClassHash
    } else {
        GatewayErrorCode::InvalidRequest
    };

    GatewayError::new(code, false, Some(message))
}
