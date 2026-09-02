use super::deploy::{
    map_deploy_provider_error, map_deploy_starknet_error, validate_open_zeppelin_descriptor,
};
use super::rpc::{is_contract_not_found, is_entrypoint_not_found, provider_transport_error};
use super::wait::{
    classify_execution, classify_transaction_status, is_transaction_hash_not_found,
    TransactionObservation,
};
use krusty_kms_common::ChainId;
use krusty_kms_domain::{
    AccountDescriptor, DerivationPath, FeltHex, GatewayErrorCode, KeyDomain, Provenance,
};
use starknet_rust::core::types::{
    ExecutionResult, StarknetError, TransactionFinalityStatus, TransactionStatus,
};
use starknet_rust::providers::ProviderError;
use starknet_types_core::felt::Felt;

fn open_zeppelin_descriptor(public_key: Felt) -> AccountDescriptor {
    AccountDescriptor {
        address: FeltHex::from_felt(Felt::from(0xa11u64)),
        public_key: FeltHex::from_felt(public_key),
        class_hash: FeltHex::from_felt(Felt::from(0xc1a55u64)),
        salt: FeltHex::from_felt(public_key),
        constructor_calldata: vec![FeltHex::from_felt(public_key)],
        deployer_address: FeltHex::from_felt(Felt::ZERO),
        provenance: Provenance {
            chain_id: ChainId::Sepolia,
            key_domain: KeyDomain::StarknetAccount,
            derivation_path: DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 0,
            },
            class_hash: None,
        },
    }
}

#[test]
fn open_zeppelin_descriptor_validation_takes_the_kms_derived_public_key() {
    let public_key = krusty_kms::stark_public_key(&Felt::from(123u64)).unwrap();
    let account = open_zeppelin_descriptor(public_key);

    assert!(validate_open_zeppelin_descriptor(&account, public_key).is_ok());

    let mismatch = validate_open_zeppelin_descriptor(&account, Felt::from(7u64)).unwrap_err();
    assert_eq!(mismatch.code, GatewayErrorCode::InvalidRequest);
    assert!(!mismatch.retryable);
}

#[test]
fn successful_preconfirmed_transactions_remain_pending() {
    assert_eq!(
        classify_execution(
            &TransactionFinalityStatus::PreConfirmed,
            &ExecutionResult::Succeeded,
        ),
        TransactionObservation::Pending
    );
}

#[test]
fn accepted_success_is_reported_as_accepted() {
    assert_eq!(
        classify_transaction_status(&TransactionStatus::AcceptedOnL2(ExecutionResult::Succeeded,)),
        TransactionObservation::Accepted
    );
}

#[test]
fn reverted_execution_is_terminal_before_acceptance() {
    assert_eq!(
        classify_transaction_status(&TransactionStatus::PreConfirmed(
            ExecutionResult::Reverted {
                reason: "constructor failed".to_string(),
            },
        )),
        TransactionObservation::Reverted {
            reason: "constructor failed".to_string(),
        }
    );
}

#[test]
fn received_and_candidate_transactions_are_pending() {
    assert_eq!(
        classify_transaction_status(&TransactionStatus::Received),
        TransactionObservation::Pending
    );
    assert_eq!(
        classify_transaction_status(&TransactionStatus::Candidate),
        TransactionObservation::Pending
    );
}

#[test]
fn transaction_hash_not_found_is_treated_as_pending_lookup_state() {
    assert!(is_transaction_hash_not_found(
        &ProviderError::StarknetError(StarknetError::TransactionHashNotFound,)
    ));
    assert!(!is_transaction_hash_not_found(&ProviderError::RateLimited));
}

#[test]
fn deploy_error_maps_typed_class_hash_failures_without_string_parsing() {
    let error = map_deploy_provider_error(ProviderError::StarknetError(
        StarknetError::ClassHashNotFound,
    ));
    assert_eq!(error.code, GatewayErrorCode::InvalidClassHash);
    assert!(!error.retryable);
}

#[test]
fn deploy_error_maps_typed_fee_failures_without_string_parsing() {
    let error = map_deploy_provider_error(ProviderError::StarknetError(
        StarknetError::InsufficientAccountBalance,
    ));
    assert_eq!(error.code, GatewayErrorCode::InsufficientFee);
    assert!(!error.retryable);
}

#[test]
fn deploy_validation_failure_still_recognizes_already_deployed_messages() {
    let error = map_deploy_starknet_error(StarknetError::ValidationFailure(
        "Requested ContractAddress has already been deployed".to_string(),
    ));
    assert_eq!(error.code, GatewayErrorCode::InvalidRequest);
    assert!(!error.retryable);
    assert_eq!(
        error.message.as_deref(),
        Some("Requested ContractAddress has already been deployed")
    );
}

#[test]
fn deploy_check_treats_only_typed_contract_not_found_as_undeployed() {
    assert!(is_contract_not_found(&ProviderError::StarknetError(
        StarknetError::ContractNotFound,
    )));
    assert!(!is_contract_not_found(&ProviderError::RateLimited));
}

#[test]
fn selector_fallback_only_triggers_on_typed_entrypoint_not_found() {
    assert!(is_entrypoint_not_found(&ProviderError::StarknetError(
        StarknetError::EntrypointNotFound,
    )));
    assert!(!is_entrypoint_not_found(&ProviderError::RateLimited));
}

#[test]
fn selector_fallback_error_keeps_primary_and_fallback_context() {
    let error = provider_transport_error(format!(
        "failed calling balance_of after typed entrypoint-not-found fallback: primary={}; fallback={}",
        ProviderError::StarknetError(StarknetError::EntrypointNotFound),
        ProviderError::RateLimited,
    ));
    assert_eq!(error.code, GatewayErrorCode::ProviderTransport);
    let message = error
        .message
        .expect("provider transport errors include a message");
    assert!(message.contains("balance_of"));
    assert!(message.contains("primary="));
    assert!(message.contains("fallback="));
}
