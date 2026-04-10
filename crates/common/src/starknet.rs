//! Starknet-specific compatibility helpers.
//!
//! These helpers codify behavior that the upstream provider surface does not
//! currently model as typed variants. They are intentionally narrow and should
//! be removed when equivalent typed information becomes available.

/// Return whether a free-form Starknet validation failure message indicates
/// that the target account contract has already been deployed.
///
/// This is a heuristic over provider message text, not a protocol-level
/// guarantee. Callers should prefer typed Starknet errors whenever possible and
/// only use this helper for the remaining validation-failure gap.
#[must_use]
pub fn is_already_deployed_validation_failure(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("contractaddress has already been deployed")
        || lower.contains("already been deployed")
        || lower.contains("alreadydeployed")
}

#[cfg(test)]
mod tests {
    use super::is_already_deployed_validation_failure;

    #[test]
    fn detects_canonical_already_deployed_message() {
        assert!(is_already_deployed_validation_failure(
            "Requested ContractAddress has already been deployed"
        ));
    }

    #[test]
    fn detects_compact_alreadydeployed_variant() {
        assert!(is_already_deployed_validation_failure(
            "Validation failed: alreadyDeployed"
        ));
    }

    #[test]
    fn ignores_unrelated_validation_failure() {
        assert!(!is_already_deployed_validation_failure(
            "Invalid transaction nonce of contract at address 0x123"
        ));
    }
}
