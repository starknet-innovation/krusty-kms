//! V3 transaction hash computation using Poseidon.
//!
//! Starknet V3 transactions use the Poseidon sponge for hashing,
//! replacing the Pedersen hash used in V0/V1/V2 transactions.

use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

// Transaction type prefixes (Cairo short strings).
const INVOKE_PREFIX: Felt = Felt::from_hex_unchecked("0x696e766f6b65"); // "invoke"
const DEPLOY_ACCOUNT_PREFIX: Felt =
    Felt::from_hex_unchecked("0x6465706c6f795f6163636f756e74"); // "deploy_account"

// Resource names (Cairo short strings).
const L1_GAS_NAME: Felt = Felt::from_hex_unchecked("0x4c315f474153"); // "L1_GAS"
const L2_GAS_NAME: Felt = Felt::from_hex_unchecked("0x4c325f474153"); // "L2_GAS"

// Power-of-two constants for resource bounds packing.
const TWO_POW_128: Felt =
    Felt::from_hex_unchecked("0x100000000000000000000000000000000");
const TWO_POW_64: Felt = Felt::from_hex_unchecked("0x10000000000000000");

// Transaction version.
const VERSION_3: Felt = Felt::from_hex_unchecked("0x3");

/// Resource bounds for a single gas type.
#[derive(Debug, Clone, Copy)]
pub struct ResourceBounds {
    pub max_amount: u64,
    pub max_price_per_unit: u128,
}

impl ResourceBounds {
    pub fn zero() -> Self {
        Self {
            max_amount: 0,
            max_price_per_unit: 0,
        }
    }
}

/// Data availability mode (L1 or L2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaMode {
    L1 = 0,
    L2 = 1,
}

/// Compute the hash of a V3 invoke transaction.
///
/// All `Felt` parameters use `starknet_types_core::felt::Felt`.
pub fn compute_invoke_v3_hash(
    sender_address: &Felt,
    calldata: &[Felt],
    chain_id: &Felt,
    nonce: &Felt,
    tip: u64,
    l1_gas: &ResourceBounds,
    l2_gas: &ResourceBounds,
    paymaster_data: &[Felt],
    account_deployment_data: &[Felt],
    nonce_da_mode: DaMode,
    fee_da_mode: DaMode,
) -> Felt {
    let fee_hash = compute_fee_hash(tip, l1_gas, l2_gas);
    let paymaster_hash = Poseidon::hash_array(paymaster_data);
    let da_mode = pack_da_modes(nonce_da_mode, fee_da_mode);
    let deployment_data_hash = Poseidon::hash_array(account_deployment_data);
    let calldata_hash = Poseidon::hash_array(calldata);

    Poseidon::hash_array(&[
        INVOKE_PREFIX,
        VERSION_3,
        *sender_address,
        fee_hash,
        paymaster_hash,
        *chain_id,
        *nonce,
        da_mode,
        deployment_data_hash,
        calldata_hash,
    ])
}

/// Compute the hash of a V3 deploy-account transaction.
///
/// All `Felt` parameters use `starknet_types_core::felt::Felt`.
pub fn compute_deploy_account_v3_hash(
    contract_address: &Felt,
    class_hash: &Felt,
    constructor_calldata: &[Felt],
    salt: &Felt,
    chain_id: &Felt,
    nonce: &Felt,
    tip: u64,
    l1_gas: &ResourceBounds,
    l2_gas: &ResourceBounds,
    paymaster_data: &[Felt],
    nonce_da_mode: DaMode,
    fee_da_mode: DaMode,
) -> Felt {
    let fee_hash = compute_fee_hash(tip, l1_gas, l2_gas);
    let paymaster_hash = Poseidon::hash_array(paymaster_data);
    let da_mode = pack_da_modes(nonce_da_mode, fee_da_mode);
    let constructor_hash = Poseidon::hash_array(constructor_calldata);

    Poseidon::hash_array(&[
        DEPLOY_ACCOUNT_PREFIX,
        VERSION_3,
        *contract_address,
        fee_hash,
        paymaster_hash,
        *chain_id,
        *nonce,
        da_mode,
        constructor_hash,
        *class_hash,
        *salt,
    ])
}

/// Compute the fee-related hash: `h(tip, l1_gas_bounds, l2_gas_bounds)`.
fn compute_fee_hash(tip: u64, l1_gas: &ResourceBounds, l2_gas: &ResourceBounds) -> Felt {
    let l1_packed = pack_resource_bounds(&L1_GAS_NAME, l1_gas);
    let l2_packed = pack_resource_bounds(&L2_GAS_NAME, l2_gas);
    Poseidon::hash_array(&[Felt::from(tip as u128), l1_packed, l2_packed])
}

/// Pack resource bounds into a single Felt:
/// `resource_name * 2^128 + max_amount * 2^64 + max_price_per_unit`
fn pack_resource_bounds(resource_name: &Felt, bounds: &ResourceBounds) -> Felt {
    *resource_name * TWO_POW_128
        + Felt::from(bounds.max_amount as u128) * TWO_POW_64
        + Felt::from(bounds.max_price_per_unit)
}

/// Pack data availability modes into a single Felt:
/// `(fee_da_mode << 32) + nonce_da_mode`
fn pack_da_modes(nonce_da: DaMode, fee_da: DaMode) -> Felt {
    Felt::from(((fee_da as u64) << 32) + nonce_da as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invoke_hash_deterministic() {
        let sender = Felt::from_hex_unchecked("0x123");
        let calldata = vec![Felt::from_hex_unchecked("0x456")];
        let chain_id = Felt::from_hex_unchecked("0x534e5f5345504f4c4941"); // SN_SEPOLIA
        let nonce = Felt::ZERO;
        let l1_gas = ResourceBounds {
            max_amount: 1000,
            max_price_per_unit: 1_000_000,
        };
        let l2_gas = ResourceBounds {
            max_amount: 5000,
            max_price_per_unit: 500_000,
        };

        let hash1 = compute_invoke_v3_hash(
            &sender,
            &calldata,
            &chain_id,
            &nonce,
            0,
            &l1_gas,
            &l2_gas,
            &[],
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        let hash2 = compute_invoke_v3_hash(
            &sender,
            &calldata,
            &chain_id,
            &nonce,
            0,
            &l1_gas,
            &l2_gas,
            &[],
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, Felt::ZERO);
    }

    #[test]
    fn test_invoke_hash_different_inputs() {
        let chain_id = Felt::from_hex_unchecked("0x534e5f5345504f4c4941");
        let l1_gas = ResourceBounds {
            max_amount: 1000,
            max_price_per_unit: 1_000_000,
        };
        let l2_gas = ResourceBounds::zero();

        let hash1 = compute_invoke_v3_hash(
            &Felt::from_hex_unchecked("0x111"),
            &[Felt::ONE],
            &chain_id,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &[],
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        let hash2 = compute_invoke_v3_hash(
            &Felt::from_hex_unchecked("0x222"),
            &[Felt::ONE],
            &chain_id,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &[],
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_deploy_account_hash_deterministic() {
        let address = Felt::from_hex_unchecked("0xABC");
        let class_hash = Felt::from_hex_unchecked("0xDEF");
        let calldata = vec![Felt::ONE, Felt::TWO];
        let salt = Felt::from_hex_unchecked("0x999");
        let chain_id = Felt::from_hex_unchecked("0x534e5f5345504f4c4941");
        let l1_gas = ResourceBounds {
            max_amount: 500,
            max_price_per_unit: 100_000,
        };
        let l2_gas = ResourceBounds::zero();

        let hash1 = compute_deploy_account_v3_hash(
            &address,
            &class_hash,
            &calldata,
            &salt,
            &chain_id,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        let hash2 = compute_deploy_account_v3_hash(
            &address,
            &class_hash,
            &calldata,
            &salt,
            &chain_id,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, Felt::ZERO);
    }

    #[test]
    fn test_invoke_differs_from_deploy() {
        let address = Felt::from_hex_unchecked("0x123");
        let class_hash = Felt::from_hex_unchecked("0x456");
        let calldata = vec![Felt::ONE];
        let chain_id = Felt::from_hex_unchecked("0x534e5f5345504f4c4941");
        let l1_gas = ResourceBounds {
            max_amount: 100,
            max_price_per_unit: 100,
        };
        let l2_gas = ResourceBounds::zero();

        let invoke_hash = compute_invoke_v3_hash(
            &address,
            &calldata,
            &chain_id,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &[],
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        let deploy_hash = compute_deploy_account_v3_hash(
            &address,
            &class_hash,
            &calldata,
            &Felt::ZERO,
            &chain_id,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        assert_ne!(invoke_hash, deploy_hash);
    }

    #[test]
    fn test_resource_bounds_packing() {
        // With zero bounds, the packed value should just be the resource name shifted
        let packed = pack_resource_bounds(&L1_GAS_NAME, &ResourceBounds::zero());
        assert_ne!(packed, Felt::ZERO);

        // With non-zero bounds, the packed value should differ
        let packed_nonzero = pack_resource_bounds(
            &L1_GAS_NAME,
            &ResourceBounds {
                max_amount: 100,
                max_price_per_unit: 200,
            },
        );
        assert_ne!(packed, packed_nonzero);
    }

    #[test]
    fn test_da_mode_packing() {
        let l1_l1 = pack_da_modes(DaMode::L1, DaMode::L1);
        assert_eq!(l1_l1, Felt::ZERO);

        let l1_l2 = pack_da_modes(DaMode::L1, DaMode::L2);
        // fee_da = L2 = 1, shifted left by 32: 2^32 = 4294967296
        assert_eq!(l1_l2, Felt::from(4294967296u64));

        let l2_l1 = pack_da_modes(DaMode::L2, DaMode::L1);
        assert_eq!(l2_l1, Felt::ONE);
    }
}
