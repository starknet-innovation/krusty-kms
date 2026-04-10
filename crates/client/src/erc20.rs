//! ERC-20 token interactions.

use crate::abi;
use crate::tx::Tx;
use crate::wallet::utils::{core_felt_to_rs, is_entrypoint_not_found, rs_felt_to_core};
use crate::wallet::WalletExecutor;
use krusty_kms_common::address::Address;
use krusty_kms_common::amount::Amount;
use krusty_kms_common::token::Token;
use krusty_kms_common::u256_to_u128;
use krusty_kms_common::{KmsError, Result};
use starknet_rust::core::codec::Decode;
use starknet_rust::core::types::ByteArray;
use starknet_rust::core::types::{BlockId, BlockTag, Call, FunctionCall};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::{Provider, ProviderError};
use std::sync::Arc;

/// An ERC-20 contract handle.
pub struct Erc20 {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    token: Token,
}

impl Erc20 {
    /// Create from a known `Token` (address + metadata).
    pub fn new(provider: Arc<JsonRpcClient<HttpTransport>>, token: Token) -> Self {
        Self { provider, token }
    }

    /// Resolve token metadata from an on-chain address.
    pub async fn from_address(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        address: Address,
    ) -> Result<Self> {
        let addr_rs = core_felt_to_rs(address.as_felt());

        let name = Self::read_string(&provider, addr_rs, *abi::erc20::NAME).await?;
        let symbol = Self::read_string(&provider, addr_rs, *abi::erc20::SYMBOL).await?;
        let decimals = Self::read_decimals(&provider, addr_rs).await?;

        let token = Token::new(address, name, symbol, decimals);
        Ok(Self { provider, token })
    }

    /// Get the token balance for an account.
    pub async fn balance_of(&self, account: &Address) -> Result<Amount> {
        let addr_rs = core_felt_to_rs(self.token.address.as_felt());
        let account_rs = core_felt_to_rs(account.as_felt());
        let result = self
            .call_erc20_with_balance_selector_fallback(addr_rs, account_rs)
            .await?;

        decode_balance_response(&result, self.token.decimals)
    }

    /// Build a `transfer` call without executing.
    pub fn populate_transfer(&self, to: &Address, amount: &Amount) -> Call {
        let (low, high) = amount.to_u256();
        Call {
            to: core_felt_to_rs(self.token.address.as_felt()),
            selector: *abi::erc20::TRANSFER,
            calldata: vec![
                core_felt_to_rs(to.as_felt()),
                core_felt_to_rs(low),
                core_felt_to_rs(high),
            ],
        }
    }

    /// Build an `approve` call without executing.
    pub fn populate_approve(&self, spender: &Address, amount: &Amount) -> Call {
        let (low, high) = amount.to_u256();
        Call {
            to: core_felt_to_rs(self.token.address.as_felt()),
            selector: *abi::erc20::APPROVE,
            calldata: vec![
                core_felt_to_rs(spender.as_felt()),
                core_felt_to_rs(low),
                core_felt_to_rs(high),
            ],
        }
    }

    /// Execute a transfer through a wallet.
    pub async fn transfer(
        &self,
        wallet: &dyn WalletExecutor,
        to: &Address,
        amount: &Amount,
    ) -> Result<Tx> {
        let call = self.populate_transfer(to, amount);
        wallet.execute(vec![call]).await
    }

    /// Execute an approval through a wallet.
    pub async fn approve(
        &self,
        wallet: &dyn WalletExecutor,
        spender: &Address,
        amount: &Amount,
    ) -> Result<Tx> {
        let call = self.populate_approve(spender, amount);
        wallet.execute(vec![call]).await
    }

    /// The underlying token metadata.
    pub fn token(&self) -> &Token {
        &self.token
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    async fn read_string(
        provider: &Arc<JsonRpcClient<HttpTransport>>,
        address: starknet_rust::core::types::Felt,
        selector: starknet_rust::core::types::Felt,
    ) -> Result<String> {
        let result = provider
            .call(
                FunctionCall {
                    contract_address: address,
                    entry_point_selector: selector,
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| KmsError::RpcError(e.to_string()))?;

        if result.is_empty() {
            return Err(KmsError::RpcError("Empty string response".into()));
        }

        decode_cairo_string(&result)
    }

    async fn read_decimals(
        provider: &Arc<JsonRpcClient<HttpTransport>>,
        address: starknet_rust::core::types::Felt,
    ) -> Result<u8> {
        let result = provider
            .call(
                FunctionCall {
                    contract_address: address,
                    entry_point_selector: *abi::erc20::DECIMALS,
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| KmsError::RpcError(e.to_string()))?;

        if result.is_empty() {
            return Err(KmsError::RpcError("Empty decimals response".into()));
        }

        let bytes = result[0].to_bytes_be();
        Ok(bytes[31])
    }

    async fn call_erc20_with_balance_selector_fallback(
        &self,
        contract_address: starknet_rust::core::types::Felt,
        account_address: starknet_rust::core::types::Felt,
    ) -> Result<Vec<starknet_rust::core::types::Felt>> {
        let primary = FunctionCall {
            contract_address,
            entry_point_selector: *abi::erc20::BALANCE_OF,
            calldata: vec![account_address],
        };

        match self
            .provider
            .call(primary, BlockId::Tag(BlockTag::Latest))
            .await
        {
            Ok(result) => Ok(result),
            Err(primary_error) if is_entrypoint_not_found(&primary_error) => {
                let fallback = FunctionCall {
                    contract_address,
                    entry_point_selector: *abi::erc20::BALANCE_OF_CAMEL,
                    calldata: vec![account_address],
                };
                self.provider
                    .call(fallback, BlockId::Tag(BlockTag::Latest))
                    .await
                    .map_err(|fallback_error| {
                        selector_fallback_error("balance_of", primary_error, fallback_error)
                    })
            }
            Err(error) => Err(KmsError::RpcError(error.to_string())),
        }
    }
}

fn decode_balance_response(
    result: &[starknet_rust::core::types::Felt],
    decimals: u8,
) -> Result<Amount> {
    if result.len() < 2 {
        return Err(KmsError::DeserializationError(format!(
            "Unexpected ERC-20 balance response length: {}",
            result.len()
        )));
    }

    let raw =
        u256_to_u128(rs_felt_to_core(result[0]), rs_felt_to_core(result[1])).map_err(|_| {
            KmsError::DeserializationError(
                "ERC-20 balance exceeds supported u128 range".to_string(),
            )
        })?;
    Ok(Amount::from_raw(raw, decimals))
}

fn decode_cairo_string(result: &[starknet_rust::core::types::Felt]) -> Result<String> {
    if result.len() == 1 {
        let bytes = result[0].to_bytes_be();
        let short = bytes
            .iter()
            .skip_while(|&&byte| byte == 0)
            .copied()
            .collect::<Vec<u8>>();
        return String::from_utf8(short).map_err(|error| {
            KmsError::DeserializationError(format!("invalid UTF-8 token metadata: {error}"))
        });
    }

    let mut iter = result.iter();
    let byte_array = ByteArray::decode_iter(&mut iter).map_err(|error| {
        KmsError::DeserializationError(format!("failed to decode Cairo ByteArray: {error}"))
    })?;
    if iter.next().is_some() {
        return Err(KmsError::DeserializationError(
            "unexpected trailing data in Cairo ByteArray response".to_string(),
        ));
    }

    String::try_from(byte_array).map_err(|error| {
        KmsError::DeserializationError(format!("invalid UTF-8 token metadata: {error}"))
    })
}

fn selector_fallback_error(
    selector: &str,
    primary_error: ProviderError,
    fallback_error: ProviderError,
) -> KmsError {
    KmsError::RpcError(format!(
        "failed calling {selector} after typed entrypoint-not-found fallback: primary={primary_error}; fallback={fallback_error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use krusty_kms_common::chain::ChainId;
    use krusty_kms_common::token::presets;
    use starknet_rust::core::codec::Encode;
    use starknet_rust::core::types::StarknetError;
    use starknet_rust::providers::ProviderError;

    #[test]
    fn test_populate_transfer() {
        let provider = Arc::new(JsonRpcClient::new(
            starknet_rust::providers::jsonrpc::HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap(),
            ),
        ));
        let token = presets::strk(ChainId::Sepolia);
        let erc20 = Erc20::new(provider, token);

        let to = Address::from_hex("0x123").unwrap();
        let amount = Amount::from_raw(1_000_000_000_000_000_000, 18);
        let call = erc20.populate_transfer(&to, &amount);

        // Should have recipient + u256 (low, high) = 3 calldata elements
        assert_eq!(call.calldata.len(), 3);
    }

    #[test]
    fn test_populate_approve() {
        let provider = Arc::new(JsonRpcClient::new(
            starknet_rust::providers::jsonrpc::HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap(),
            ),
        ));
        let token = presets::eth(ChainId::Mainnet);
        let erc20 = Erc20::new(provider, token);

        let spender = Address::from_hex("0xabc").unwrap();
        let amount = Amount::from_raw(500, 18);
        let call = erc20.populate_approve(&spender, &amount);

        assert_eq!(call.calldata.len(), 3);
    }

    #[test]
    fn test_decode_balance_response_rejects_values_above_u128() {
        let error = decode_balance_response(
            &[
                starknet_rust::core::types::Felt::ZERO,
                starknet_rust::core::types::Felt::ONE,
            ],
            18,
        )
        .unwrap_err();

        assert!(matches!(error, KmsError::DeserializationError(_)));
    }

    #[test]
    fn test_decode_cairo_string_supports_byte_array_metadata() {
        let mut encoded = Vec::new();
        ByteArray::from("Wrapped Starknet Governance Token")
            .encode(&mut encoded)
            .unwrap();

        assert_eq!(
            decode_cairo_string(&encoded).unwrap(),
            "Wrapped Starknet Governance Token"
        );
    }

    #[test]
    fn test_selector_fallback_error_preserves_primary_and_fallback_context() {
        let error = selector_fallback_error(
            "balance_of",
            ProviderError::StarknetError(StarknetError::EntrypointNotFound),
            ProviderError::RateLimited,
        );

        let message = match error {
            KmsError::RpcError(message) => message,
            other => panic!("unexpected error: {other:?}"),
        };
        assert!(message.contains("balance_of"));
        assert!(message.contains("primary="));
        assert!(message.contains("fallback="));
    }
}
