//! Session policies and fee mode types for the Cartridge Controller.

use crate::convert::felt_ours_to_sdk;
use account_sdk::account::session::policy::{CallPolicy, Policy};
use krusty_kms_common::address::Address;
use krusty_kms_common::{KmsError, Result};

/// A simplified session policy matching the StarkZap `{ target, method }` format.
#[derive(Debug, Clone)]
pub struct SessionPolicy {
    /// The contract address this policy authorizes calls to.
    target: Address,
    /// The entry-point name (e.g. `"transfer"`).
    method: String,
    selector: starknet::core::types::Felt,
}

impl SessionPolicy {
    /// Create a new session policy.
    pub fn new(target: Address, method: impl Into<String>) -> Result<Self> {
        let method = method.into();
        if method.trim().is_empty() {
            return Err(KmsError::ControllerError(
                "session policy method must not be empty".to_string(),
            ));
        }
        let selector = starknet::core::utils::get_selector_from_name(&method).map_err(|error| {
            KmsError::ControllerError(format!("invalid session policy method {method:?}: {error}"))
        })?;

        Ok(Self {
            target,
            method,
            selector,
        })
    }

    /// The contract address this policy authorizes calls to.
    pub fn target(&self) -> &Address {
        &self.target
    }

    /// The entry-point name this policy authorizes.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Convert to the SDK's `Policy::Call` type.
    pub fn to_sdk_policy(&self) -> Policy {
        Policy::Call(CallPolicy {
            contract_address: felt_ours_to_sdk(self.target.as_felt()),
            selector: self.selector,
            authorized: Some(true),
        })
    }
}

/// Fee mode for Controller transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeMode {
    /// User pays gas (standard `execute_v3`).
    UserPays,
    /// Cartridge paymaster sponsors gas (`execute_from_outside_v3`).
    Sponsored,
    /// Use Cartridge credits.
    Credits,
}

/// Build ERC-20 session policies for a token (transfer + approve).
pub fn erc20_policies(token: &Address) -> Vec<SessionPolicy> {
    vec![
        literal_policy(*token, "transfer"),
        literal_policy(*token, "approve"),
    ]
}

/// Build staking session policies for a pool and its staking token.
pub fn staking_policies(pool: &Address, token: &Address) -> Vec<SessionPolicy> {
    let mut policies = erc20_policies(token);
    policies.extend([
        literal_policy(*pool, "enter_delegation_pool"),
        literal_policy(*pool, "add_to_delegation_pool"),
        literal_policy(*pool, "exit_delegation_pool_intent"),
        literal_policy(*pool, "exit_delegation_pool_action"),
        literal_policy(*pool, "claim_rewards"),
    ]);
    policies
}

fn literal_policy(target: Address, method: &'static str) -> SessionPolicy {
    SessionPolicy::new(target, method).expect("literal session policy method must be valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_policy_to_sdk() {
        let addr =
            Address::from_hex("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
                .unwrap();
        let policy = SessionPolicy::new(addr, "transfer").unwrap();
        let sdk = policy.to_sdk_policy();

        match sdk {
            Policy::Call(cp) => {
                // Selector for "transfer"
                let expected = starknet::core::utils::get_selector_from_name("transfer").unwrap();
                assert_eq!(cp.selector, expected);
                assert_eq!(cp.authorized, Some(true));
            }
            _ => panic!("expected CallPolicy"),
        }
    }

    #[test]
    fn erc20_policies_count() {
        let addr = Address::from_hex("0x1").unwrap();
        let policies = erc20_policies(&addr);
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].method(), "transfer");
        assert_eq!(policies[1].method(), "approve");
    }

    #[test]
    fn staking_policies_count() {
        let pool = Address::from_hex("0xDEAD").unwrap();
        let token = Address::from_hex("0xBEEF").unwrap();
        let policies = staking_policies(&pool, &token);
        // 2 erc20 + 5 staking = 7
        assert_eq!(policies.len(), 7);
    }

    #[test]
    fn session_policy_rejects_invalid_method_names() {
        let addr = Address::from_hex("0x1").unwrap();
        let error = SessionPolicy::new(addr, "transfer🙂").unwrap_err();
        assert!(matches!(error, KmsError::ControllerError(_)));
    }

    #[test]
    fn session_policy_rejects_empty_method_names() {
        let addr = Address::from_hex("0x1").unwrap();
        let error = SessionPolicy::new(addr, "   ").unwrap_err();
        assert!(matches!(error, KmsError::ControllerError(_)));
    }
}
