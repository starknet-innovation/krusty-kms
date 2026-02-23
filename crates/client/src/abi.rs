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
    pub static BALANCE_OF_CAMEL: LazyLock<StarknetRsFelt> =
        LazyLock::new(|| selector("balanceOf"));
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
}
