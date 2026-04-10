//! V3 transaction hash computation — delegates to `krusty_kms::tx_hash`.
//!
//! This module re-exports and wraps the canonical hash implementation from
//! the KMS crate, ensuring a single source of truth for hash computation
//! across the entire workspace.

use starknet_types_core::felt::Felt;

// Re-export KMS types for backward compatibility.
pub use krusty_kms::tx_hash::{DaMode, ResourceBounds};

/// Fee-related parameters for V3 transactions.
///
/// Wraps the individual fields expected by the KMS hash functions into a
/// single struct for ergonomic use in the client crate.
pub struct V3TxFeeConfig<'a> {
    pub tip: u64,
    pub l1_gas: &'a ResourceBounds,
    pub l2_gas: &'a ResourceBounds,
    pub l1_data_gas: &'a ResourceBounds,
    pub paymaster_data: &'a [Felt],
    pub nonce_da_mode: DaMode,
    pub fee_da_mode: DaMode,
}

/// Compute the hash of a V3 invoke transaction.
///
/// Delegates to [`krusty_kms::tx_hash::compute_invoke_v3_hash`].
pub fn compute_invoke_v3_hash(
    sender_address: &Felt,
    calldata: &[Felt],
    chain_id: &Felt,
    nonce: &Felt,
    account_deployment_data: &[Felt],
    fee: &V3TxFeeConfig,
) -> Felt {
    krusty_kms::compute_invoke_v3_hash(
        sender_address,
        calldata,
        chain_id,
        nonce,
        account_deployment_data,
        fee.tip,
        fee.l1_gas,
        fee.l2_gas,
        fee.l1_data_gas,
        fee.paymaster_data,
        fee.nonce_da_mode,
        fee.fee_da_mode,
    )
}

/// Compute the hash of a V3 deploy-account transaction.
///
/// Delegates to [`krusty_kms::tx_hash::compute_deploy_account_v3_hash`].
pub fn compute_deploy_account_v3_hash(
    contract_address: &Felt,
    class_hash: &Felt,
    constructor_calldata: &[Felt],
    salt: &Felt,
    chain_id: &Felt,
    nonce: &Felt,
    fee: &V3TxFeeConfig,
) -> Felt {
    krusty_kms::compute_deploy_account_v3_hash(
        contract_address,
        class_hash,
        constructor_calldata,
        salt,
        chain_id,
        nonce,
        fee.tip,
        fee.l1_gas,
        fee.l2_gas,
        fee.l1_data_gas,
        fee.paymaster_data,
        fee.nonce_da_mode,
        fee.fee_da_mode,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SN_SEPOLIA: Felt = Felt::from_hex_unchecked("0x534e5f5345504f4c4941");

    const ZERO_BOUNDS: ResourceBounds = ResourceBounds {
        max_amount: 0,
        max_price_per_unit: 0,
    };

    fn default_fee_config<'a>(
        l1_gas: &'a ResourceBounds,
        l2_gas: &'a ResourceBounds,
    ) -> V3TxFeeConfig<'a> {
        V3TxFeeConfig {
            tip: 0,
            l1_gas,
            l2_gas,
            l1_data_gas: &ZERO_BOUNDS,
            paymaster_data: &[],
            nonce_da_mode: DaMode::L1,
            fee_da_mode: DaMode::L1,
        }
    }

    /// The wrapper must produce the exact same hash as a direct call to
    /// `krusty_kms::compute_invoke_v3_hash`.
    #[test]
    fn invoke_v3_delegates_to_kms() {
        let sender = Felt::from_hex_unchecked("0x123");
        let calldata = vec![Felt::from_hex_unchecked("0x456")];
        let nonce = Felt::ZERO;
        let l1_gas = ResourceBounds {
            max_amount: 1000,
            max_price_per_unit: 1_000_000,
        };
        let l2_gas = ResourceBounds {
            max_amount: 5000,
            max_price_per_unit: 500_000,
        };
        let fee = default_fee_config(&l1_gas, &l2_gas);

        let via_wrapper =
            compute_invoke_v3_hash(&sender, &calldata, &SN_SEPOLIA, &nonce, &[], &fee);

        let via_kms = krusty_kms::compute_invoke_v3_hash(
            &sender,
            &calldata,
            &SN_SEPOLIA,
            &nonce,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ZERO_BOUNDS,
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        assert_eq!(via_wrapper, via_kms);
        assert_ne!(via_wrapper, Felt::ZERO);
    }

    /// The wrapper must produce the exact same hash as a direct call to
    /// `krusty_kms::compute_deploy_account_v3_hash`.
    #[test]
    fn deploy_account_v3_delegates_to_kms() {
        let address = Felt::from_hex_unchecked("0xABC");
        let class_hash = Felt::from_hex_unchecked("0xDEF");
        let calldata = vec![Felt::ONE, Felt::TWO];
        let salt = Felt::from_hex_unchecked("0x999");
        let l1_gas = ResourceBounds {
            max_amount: 500,
            max_price_per_unit: 100_000,
        };
        let l2_gas = ResourceBounds::zero();
        let fee = default_fee_config(&l1_gas, &l2_gas);

        let via_wrapper = compute_deploy_account_v3_hash(
            &address,
            &class_hash,
            &calldata,
            &salt,
            &SN_SEPOLIA,
            &Felt::ZERO,
            &fee,
        );

        let via_kms = krusty_kms::compute_deploy_account_v3_hash(
            &address,
            &class_hash,
            &calldata,
            &salt,
            &SN_SEPOLIA,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &ZERO_BOUNDS,
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        assert_eq!(via_wrapper, via_kms);
        assert_ne!(via_wrapper, Felt::ZERO);
    }

    /// Different inputs must produce different hashes.
    #[test]
    fn invoke_v3_different_inputs() {
        let l1_gas = ResourceBounds {
            max_amount: 1000,
            max_price_per_unit: 1_000_000,
        };
        let l2_gas = ResourceBounds::zero();
        let fee = default_fee_config(&l1_gas, &l2_gas);

        let hash1 = compute_invoke_v3_hash(
            &Felt::from_hex_unchecked("0x111"),
            &[Felt::ONE],
            &SN_SEPOLIA,
            &Felt::ZERO,
            &[],
            &fee,
        );

        let hash2 = compute_invoke_v3_hash(
            &Felt::from_hex_unchecked("0x222"),
            &[Felt::ONE],
            &SN_SEPOLIA,
            &Felt::ZERO,
            &[],
            &fee,
        );

        assert_ne!(hash1, hash2);
    }

    /// Invoke and deploy-account must produce different hashes for the same address.
    #[test]
    fn invoke_differs_from_deploy() {
        let address = Felt::from_hex_unchecked("0x123");
        let class_hash = Felt::from_hex_unchecked("0x456");
        let calldata = vec![Felt::ONE];
        let l1_gas = ResourceBounds {
            max_amount: 100,
            max_price_per_unit: 100,
        };
        let l2_gas = ResourceBounds::zero();
        let fee = default_fee_config(&l1_gas, &l2_gas);

        let invoke_hash =
            compute_invoke_v3_hash(&address, &calldata, &SN_SEPOLIA, &Felt::ZERO, &[], &fee);

        let deploy_hash = compute_deploy_account_v3_hash(
            &address,
            &class_hash,
            &calldata,
            &Felt::ZERO,
            &SN_SEPOLIA,
            &Felt::ZERO,
            &fee,
        );

        assert_ne!(invoke_hash, deploy_hash);
    }
}
