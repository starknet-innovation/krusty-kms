//! STRK staking delegation pool operations.

use crate::abi;
use crate::tx::Tx;
use crate::wallet::utils::{self, core_felt_to_rs, rs_felt_to_core};
use crate::wallet::Wallet;
use krusty_kms_common::address::Address;
use krusty_kms_common::amount::Amount;
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::token::Token;
use krusty_kms_common::{KmsError, Result};
use std::sync::Arc;
use starknet_rust::core::types::{BlockId, BlockTag, Call, FunctionCall};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;

/// Mainnet staking contract address.
const MAINNET_STAKING_CONTRACT: &str =
    "0x0594c1582459ea03f77deaf9eb7e3917d6994a03c13405ba42867f83d85f085d";
/// Sepolia staking contract address.
const SEPOLIA_STAKING_CONTRACT: &str =
    "0x03745ab04a431fc02871a139be6b93d9260b0ff3e779ad9c8b377183b23109f1";

/// Get the staking contract address for a given chain.
pub fn staking_contract_address(chain_id: ChainId) -> Address {
    match chain_id {
        ChainId::Mainnet => Address::from_hex(MAINNET_STAKING_CONTRACT).unwrap(),
        ChainId::Sepolia => Address::from_hex(SEPOLIA_STAKING_CONTRACT).unwrap(),
    }
}

/// A handle for interacting with a staking delegation pool.
pub struct Staking {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    pool_address: Address,
    token: Token,
}

/// A pool member's staking position.
#[derive(Debug, Clone)]
pub struct PoolPosition {
    pub reward_address: Address,
    pub amount: Amount,
    pub unclaimed_rewards: Amount,
    pub commission: u16,
}

impl Staking {
    /// Create a staking handle from a known pool address and token.
    pub fn new(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        pool_address: Address,
        token: Token,
    ) -> Self {
        Self {
            provider,
            pool_address,
            token,
        }
    }

    /// Build calls to enter a delegation pool: approve + enter_delegation_pool.
    pub fn populate_enter(&self, amount: &Amount, reward_address: &Address) -> Vec<Call> {
        let pool_rs = core_felt_to_rs(self.pool_address.as_felt());
        let (low, high) = amount.to_u256();

        let approve = Call {
            to: core_felt_to_rs(self.token.address.as_felt()),
            selector: *abi::erc20::APPROVE,
            calldata: vec![pool_rs, core_felt_to_rs(low), core_felt_to_rs(high)],
        };

        let enter = Call {
            to: pool_rs,
            selector: *abi::pool::ENTER_DELEGATION_POOL,
            calldata: vec![
                core_felt_to_rs(reward_address.as_felt()),
                core_felt_to_rs(low),
                core_felt_to_rs(high),
            ],
        };

        vec![approve, enter]
    }

    /// Build calls to add more stake: approve + add_to_delegation_pool.
    pub fn populate_add(&self, amount: &Amount) -> Vec<Call> {
        let pool_rs = core_felt_to_rs(self.pool_address.as_felt());
        let (low, high) = amount.to_u256();

        let approve = Call {
            to: core_felt_to_rs(self.token.address.as_felt()),
            selector: *abi::erc20::APPROVE,
            calldata: vec![pool_rs, core_felt_to_rs(low), core_felt_to_rs(high)],
        };

        let add = Call {
            to: pool_rs,
            selector: *abi::pool::ADD_TO_DELEGATION_POOL,
            calldata: vec![core_felt_to_rs(low), core_felt_to_rs(high)],
        };

        vec![approve, add]
    }

    /// Build a claim_rewards call.
    pub fn populate_claim_rewards(&self, reward_address: &Address) -> Call {
        Call {
            to: core_felt_to_rs(self.pool_address.as_felt()),
            selector: *abi::pool::CLAIM_REWARDS,
            calldata: vec![core_felt_to_rs(reward_address.as_felt())],
        }
    }

    /// Build an exit_delegation_pool_intent call.
    pub fn populate_exit_intent(&self, amount: &Amount) -> Call {
        let (low, high) = amount.to_u256();
        Call {
            to: core_felt_to_rs(self.pool_address.as_felt()),
            selector: *abi::pool::EXIT_INTENT,
            calldata: vec![core_felt_to_rs(low), core_felt_to_rs(high)],
        }
    }

    /// Build an exit_delegation_pool_action call.
    pub fn populate_exit(&self) -> Call {
        Call {
            to: core_felt_to_rs(self.pool_address.as_felt()),
            selector: *abi::pool::EXIT_ACTION,
            calldata: vec![],
        }
    }

    /// Check if an address is a pool member.
    pub async fn is_member(&self, address: &Address) -> Result<bool> {
        match self.get_position(address).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get a member's staking position.
    pub async fn get_position(&self, address: &Address) -> Result<PoolPosition> {
        let pool_rs = core_felt_to_rs(self.pool_address.as_felt());
        let addr_rs = core_felt_to_rs(address.as_felt());

        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: pool_rs,
                    entry_point_selector: *abi::pool::POOL_MEMBER_INFO,
                    calldata: vec![addr_rs],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| KmsError::StakingError(e.to_string()))?;

        // Parse pool_member_info response
        // Expected: reward_address, amount (u256), unclaimed_rewards (u256), commission (u16), ...
        if result.len() < 6 {
            return Err(KmsError::StakingError(
                "Unexpected pool_member_info response length".into(),
            ));
        }

        let reward_address = Address::from(rs_felt_to_core(result[0]));
        let amount_raw = utils::felt_to_u128(&result[1]);
        let unclaimed_raw = utils::felt_to_u128(&result[3]);
        let commission = utils::felt_to_u16(&result[5]);

        Ok(PoolPosition {
            reward_address,
            amount: Amount::from_raw(amount_raw, self.token.decimals),
            unclaimed_rewards: Amount::from_raw(unclaimed_raw, self.token.decimals),
            commission,
        })
    }

    /// Get the pool commission rate (basis points).
    pub async fn get_commission(&self) -> Result<u16> {
        let pool_rs = core_felt_to_rs(self.pool_address.as_felt());
        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: pool_rs,
                    entry_point_selector: *abi::pool::CONTRACT_PARAMETERS,
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| KmsError::StakingError(e.to_string()))?;

        if result.is_empty() {
            return Err(KmsError::StakingError(
                "Empty contract_parameters response".into(),
            ));
        }

        // Commission is typically the first field
        Ok(utils::felt_to_u16(&result[0]))
    }

    /// Stake: if already a member, adds to pool; otherwise enters as new member.
    pub async fn stake(
        &self,
        wallet: &Wallet,
        amount: &Amount,
        reward_address: &Address,
    ) -> Result<Tx> {
        let is_existing = self.is_member(wallet.address()).await?;
        let calls = if is_existing {
            self.populate_add(amount)
        } else {
            self.populate_enter(amount, reward_address)
        };
        wallet.execute(calls).await
    }

    /// The pool address.
    pub fn pool_address(&self) -> &Address {
        &self.pool_address
    }

    /// The staking token.
    pub fn token(&self) -> &Token {
        &self.token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staking_contract_addresses() {
        let mainnet = staking_contract_address(ChainId::Mainnet);
        let sepolia = staking_contract_address(ChainId::Sepolia);
        assert_ne!(mainnet.as_felt(), sepolia.as_felt());
    }

    #[test]
    fn test_populate_enter() {
        let provider = Arc::new(JsonRpcClient::new(
            starknet_rust::providers::jsonrpc::HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap(),
            ),
        ));
        let token = krusty_kms_common::token::presets::strk(ChainId::Mainnet);
        let pool = Address::from_hex("0xDEAD").unwrap();
        let staking = Staking::new(provider, pool, token);

        let amount = Amount::from_raw(1_000_000_000_000_000_000, 18);
        let reward = Address::from_hex("0xBEEF").unwrap();
        let calls = staking.populate_enter(&amount, &reward);

        // approve + enter = 2 calls
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn test_populate_add() {
        let provider = Arc::new(JsonRpcClient::new(
            starknet_rust::providers::jsonrpc::HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap(),
            ),
        ));
        let token = krusty_kms_common::token::presets::strk(ChainId::Mainnet);
        let pool = Address::from_hex("0xDEAD").unwrap();
        let staking = Staking::new(provider, pool, token);

        let amount = Amount::from_raw(500, 18);
        let calls = staking.populate_add(&amount);

        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn test_populate_exit() {
        let provider = Arc::new(JsonRpcClient::new(
            starknet_rust::providers::jsonrpc::HttpTransport::new(
                url::Url::parse("http://localhost:5050").unwrap(),
            ),
        ));
        let token = krusty_kms_common::token::presets::strk(ChainId::Mainnet);
        let pool = Address::from_hex("0xDEAD").unwrap();
        let staking = Staking::new(provider, pool, token);

        let call = staking.populate_exit();
        assert!(call.calldata.is_empty());
    }
}
