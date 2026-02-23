//! ERC-20 token interactions.

use crate::abi;
use crate::tx::Tx;
use crate::wallet::utils::{self, core_felt_to_rs};
use crate::wallet::WalletExecutor;
use krusty_kms_common::address::Address;
use krusty_kms_common::amount::Amount;
use krusty_kms_common::token::Token;
use krusty_kms_common::{KmsError, Result};
use std::sync::Arc;
use starknet_rust::core::types::{BlockId, BlockTag, Call, FunctionCall};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;

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

        // Try snake_case first, fall back to camelCase
        let result = match self
            .provider
            .call(
                FunctionCall {
                    contract_address: addr_rs,
                    entry_point_selector: *abi::erc20::BALANCE_OF,
                    calldata: vec![account_rs],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
        {
            Ok(r) => r,
            Err(_) => {
                // Try camelCase variant
                self.provider
                    .call(
                        FunctionCall {
                            contract_address: addr_rs,
                            entry_point_selector: *abi::erc20::BALANCE_OF_CAMEL,
                            calldata: vec![account_rs],
                        },
                        BlockId::Tag(BlockTag::Latest),
                    )
                    .await
                    .map_err(|e| KmsError::RpcError(e.to_string()))?
            }
        };

        if result.is_empty() {
            return Err(KmsError::RpcError("Empty balance response".into()));
        }

        // u256 is returned as (low, high)
        let low = utils::felt_to_u128(&result[0]);
        let high = if result.len() > 1 {
            utils::felt_to_u128(&result[1])
        } else {
            0
        };

        // Combine into u128 (high should be 0 for typical token balances)
        let raw = if high > 0 {
            // Very large balance — saturate at u128::MAX
            u128::MAX
        } else {
            low
        };

        Ok(Amount::from_raw(raw, self.token.decimals))
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

        // Cairo short-string is returned as a single Felt
        let bytes = result[0].to_bytes_be();
        let s = bytes
            .iter()
            .skip_while(|&&b| b == 0)
            .copied()
            .collect::<Vec<u8>>();
        String::from_utf8(s).map_err(|e| KmsError::DeserializationError(e.to_string()))
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use krusty_kms_common::token::presets;
    use krusty_kms_common::chain::ChainId;

    #[test]
    fn test_populate_transfer() {
        let provider = Arc::new(
            JsonRpcClient::new(starknet_rust::providers::jsonrpc::HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap(),
            )),
        );
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
        let provider = Arc::new(
            JsonRpcClient::new(starknet_rust::providers::jsonrpc::HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap(),
            )),
        );
        let token = presets::eth(ChainId::Mainnet);
        let erc20 = Erc20::new(provider, token);

        let spender = Address::from_hex("0xabc").unwrap();
        let amount = Amount::from_raw(500, 18);
        let call = erc20.populate_approve(&spender, &amount);

        assert_eq!(call.calldata.len(), 3);
    }
}
