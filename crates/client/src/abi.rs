//! Pre-computed ABI selectors for Starknet contract interactions.
//!
//! All selectors are computed lazily on first access via `LazyLock`.

use std::sync::LazyLock;

type StarknetRsFelt = starknet_rust::core::types::Felt;

fn selector(name: &str) -> StarknetRsFelt {
    starknet_rust::core::utils::get_selector_from_name(name)
        .expect("selector computation should not fail for valid ASCII names")
}

/// ERC-20 token ABI selectors.
pub mod erc20 {
    use super::*;

    pub static NAME: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("name"));
    pub static SYMBOL: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("symbol"));
    pub static DECIMALS: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("decimals"));
    pub static BALANCE_OF: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("balance_of"));
    pub static BALANCE_OF_CAMEL: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("balanceOf"));
    pub static APPROVE: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("approve"));
    pub static TRANSFER: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("transfer"));
}

/// Staking delegation pool ABI selectors.
pub mod pool {
    use super::*;

    pub static ENTER_DELEGATION_POOL: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| selector("enter_delegation_pool"));
    pub static ADD_TO_DELEGATION_POOL: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| selector("add_to_delegation_pool"));
    pub static EXIT_INTENT: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| selector("exit_delegation_pool_intent"));
    pub static EXIT_ACTION: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| selector("exit_delegation_pool_action"));
    pub static CLAIM_REWARDS: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| selector("claim_rewards"));
    pub static POOL_MEMBER_INFO: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| selector("pool_member_info"));
    pub static CONTRACT_PARAMETERS: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| selector("contract_parameters"));
}

/// Tongo contract ABI selectors.
pub mod tongo {
    use super::*;

    pub static FUND: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("fund"));
    pub static OUTSIDE_FUND: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("outside_fund"));
    pub static ROLLOVER: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("rollover"));
    pub static WITHDRAW: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("withdraw"));
    pub static TRANSFER: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("transfer"));
    pub static RAGEQUIT: LazyLock<StarknetRsFelt> = LazyLock::new(|| selector("ragequit"));
}

/// Tongo event selectors (starknet_keccak of event name).
pub mod tongo_events {
    use super::*;

    fn event_selector(name: &str) -> StarknetRsFelt {
        starknet_rust::core::utils::starknet_keccak(name.as_bytes())
    }

    pub static FUND_EVENT: LazyLock<StarknetRsFelt> = LazyLock::new(|| event_selector("FundEvent"));
    pub static OUTSIDE_FUND_EVENT: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| event_selector("OutsideFundEvent"));
    pub static ROLLOVER_EVENT: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| event_selector("RolloverEvent"));
    pub static TRANSFER_EVENT: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| event_selector("TransferEvent"));
    pub static WITHDRAW_EVENT: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| event_selector("WithdrawEvent"));
    pub static RAGEQUIT_EVENT: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| event_selector("RagequitEvent"));
    pub static BALANCE_DECLARED_EVENT: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| event_selector("BalanceDeclaredEvent"));
    pub static TRANSFER_DECLARED_EVENT: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| event_selector("TransferDeclaredEvent"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erc20_selectors_non_zero() {
        assert_ne!(*erc20::TRANSFER, StarknetRsFelt::ZERO);
        assert_ne!(*erc20::APPROVE, StarknetRsFelt::ZERO);
        assert_ne!(*erc20::BALANCE_OF, StarknetRsFelt::ZERO);
    }

    #[test]
    fn test_pool_selectors_non_zero() {
        assert_ne!(*pool::ENTER_DELEGATION_POOL, StarknetRsFelt::ZERO);
        assert_ne!(*pool::CLAIM_REWARDS, StarknetRsFelt::ZERO);
    }

    #[test]
    fn test_selectors_are_different() {
        assert_ne!(*erc20::TRANSFER, *erc20::APPROVE);
        assert_ne!(*erc20::BALANCE_OF, *erc20::BALANCE_OF_CAMEL);
    }

    #[test]
    fn test_tongo_selectors_non_zero() {
        assert_ne!(*tongo::FUND, StarknetRsFelt::ZERO);
        assert_ne!(*tongo::OUTSIDE_FUND, StarknetRsFelt::ZERO);
        assert_ne!(*tongo::ROLLOVER, StarknetRsFelt::ZERO);
        assert_ne!(*tongo::WITHDRAW, StarknetRsFelt::ZERO);
        assert_ne!(*tongo::TRANSFER, StarknetRsFelt::ZERO);
        assert_ne!(*tongo::RAGEQUIT, StarknetRsFelt::ZERO);
    }

    #[test]
    fn test_tongo_event_selectors_non_zero() {
        assert_ne!(*tongo_events::FUND_EVENT, StarknetRsFelt::ZERO);
        assert_ne!(*tongo_events::OUTSIDE_FUND_EVENT, StarknetRsFelt::ZERO);
        assert_ne!(*tongo_events::ROLLOVER_EVENT, StarknetRsFelt::ZERO);
        assert_ne!(*tongo_events::TRANSFER_EVENT, StarknetRsFelt::ZERO);
        assert_ne!(*tongo_events::WITHDRAW_EVENT, StarknetRsFelt::ZERO);
        assert_ne!(*tongo_events::RAGEQUIT_EVENT, StarknetRsFelt::ZERO);
        assert_ne!(*tongo_events::BALANCE_DECLARED_EVENT, StarknetRsFelt::ZERO);
        assert_ne!(*tongo_events::TRANSFER_DECLARED_EVENT, StarknetRsFelt::ZERO);
    }
}
