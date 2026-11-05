//! Shared JSON-RPC helpers: typed error checks, felt conversions, block ids,
//! and the ERC-20 `balance_of` selector fallback.

use super::StarknetRsFelt;
use crate::GatewayResult;
use krusty_kms_domain::{BlockSelector, GatewayError, GatewayErrorCode};
pub(super) use krusty_kms_wallet_api::provider_error_message;
use krusty_kms_wallet_api::StarknetRpcClient;
use num_bigint::BigUint;
use starknet_rust_core::types::{BlockId, BlockTag, FunctionCall, StarknetError};
use starknet_rust_core::utils::get_selector_from_name;
use starknet_rust_providers::{Provider, ProviderError};
use starknet_types_core::felt::Felt as CoreFelt;
use std::sync::Arc;

pub(super) fn provider_transport_error(message: String) -> GatewayError {
    GatewayError::new(GatewayErrorCode::ProviderTransport, true, Some(message))
}

/// Map a provider failure to a retryable `ProviderTransport` error whose
/// message is safe to store and return: gateway messages end up in oracle
/// responses and the operation store, and `reqwest::Error`'s `Display`
/// embeds the endpoint URL (see [`provider_error_message`]).
pub(super) fn map_provider_error(error: ProviderError) -> GatewayError {
    provider_transport_error(provider_error_message(&error))
}

pub(super) fn is_contract_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::ContractNotFound)
    )
}

pub(super) fn is_entrypoint_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::EntrypointNotFound)
    )
}

pub(super) async fn call_erc20_balance_with_selector_fallback(
    provider: &Arc<StarknetRpcClient>,
    primary_call: FunctionCall,
    block_id: BlockId,
    fallback_call: FunctionCall,
) -> GatewayResult<Vec<StarknetRsFelt>> {
    match provider.call(primary_call, block_id).await {
        Ok(result) => Ok(result),
        Err(primary_error) if is_entrypoint_not_found(&primary_error) => {
            provider
                .call(fallback_call, block_id)
                .await
                .map_err(|fallback_error| {
                    provider_transport_error(format!(
                        "failed calling balance_of after typed entrypoint-not-found fallback: primary={primary_error}; fallback={}",
                        provider_error_message(&fallback_error)
                    ))
                })
        }
        Err(error) => Err(map_provider_error(error)),
    }
}

pub(super) fn to_block_id(block: &BlockSelector) -> BlockId {
    match block {
        BlockSelector::Latest => BlockId::Tag(BlockTag::Latest),
        BlockSelector::Pending => BlockId::Tag(BlockTag::PreConfirmed),
        BlockSelector::Number(number) => BlockId::Number(*number),
        BlockSelector::Hash(hash) => BlockId::Hash(core_felt_to_rs(hash.to_felt())),
    }
}

pub(super) fn core_felt_to_rs(felt: CoreFelt) -> StarknetRsFelt {
    StarknetRsFelt::from_bytes_be(&felt.to_bytes_be())
}

pub(super) fn rs_felt_to_core(felt: StarknetRsFelt) -> CoreFelt {
    CoreFelt::from_bytes_be(&felt.to_bytes_be())
}

pub(super) fn rs_felt_to_biguint(felt: &StarknetRsFelt) -> BigUint {
    BigUint::from_bytes_be(&felt.to_bytes_be())
}

pub(super) fn balance_of_selector() -> StarknetRsFelt {
    get_selector_from_name("balance_of").expect("literal selector name must be valid")
}

pub(super) fn balance_of_camel_selector() -> StarknetRsFelt {
    get_selector_from_name("balanceOf").expect("literal selector name must be valid")
}
