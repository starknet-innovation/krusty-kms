//! Transaction hash computation for Starknet V1, V2, and V3 transactions.
//!
//! - **V1/V2** transactions use Pedersen-based `computeHashOnElements`.
//! - **V3** transactions use the Poseidon sponge hash.
//!
//! All hash functions are deterministic and infallible, returning `Felt` directly.

use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use crate::account::hash_elements;

// ---------------------------------------------------------------------------
// Transaction type prefixes (Cairo short strings)
// ---------------------------------------------------------------------------

const INVOKE_PREFIX: Felt = Felt::from_hex_unchecked("0x696e766f6b65"); // "invoke"
const DEPLOY_ACCOUNT_PREFIX: Felt = Felt::from_hex_unchecked("0x6465706c6f795f6163636f756e74"); // "deploy_account"
const DECLARE_PREFIX: Felt = Felt::from_hex_unchecked("0x6465636c617265"); // "declare"

// ---------------------------------------------------------------------------
// Resource names (Cairo short strings)
// ---------------------------------------------------------------------------

const L1_GAS_NAME: Felt = Felt::from_hex_unchecked("0x4c315f474153"); // "L1_GAS"
const L2_GAS_NAME: Felt = Felt::from_hex_unchecked("0x4c325f474153"); // "L2_GAS"
const L1_DATA_NAME: Felt = Felt::from_hex_unchecked("0x4c315f44415441"); // "L1_DATA"

// ---------------------------------------------------------------------------
// Packing constants
// ---------------------------------------------------------------------------

/// 2^192 — used to position the resource name in packed resource bounds.
const TWO_POW_192: Felt =
    Felt::from_hex_unchecked("0x1000000000000000000000000000000000000000000000000");

/// 2^128 — used to position `max_amount` in packed resource bounds.
const TWO_POW_128: Felt = Felt::from_hex_unchecked("0x100000000000000000000000000000000");

// ---------------------------------------------------------------------------
// Transaction versions
// ---------------------------------------------------------------------------

const VERSION_1: Felt = Felt::from_hex_unchecked("0x1");
const VERSION_2: Felt = Felt::from_hex_unchecked("0x2");
const VERSION_3: Felt = Felt::from_hex_unchecked("0x3");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Resource bounds for a single gas type (L1 or L2).
#[derive(Debug, Clone, Copy)]
pub struct ResourceBounds {
    pub max_amount: u64,
    pub max_price_per_unit: u128,
}

impl ResourceBounds {
    /// Zero resource bounds (no gas budget).
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

// ===========================================================================
// V1 / V2 transaction hashes (Pedersen)
// ===========================================================================

/// Compute the hash of a V1 invoke transaction.
///
/// Formula:
/// ```text
/// hash_elements([
///     INVOKE_PREFIX, VERSION_1, sender_address, 0,
///     hash_elements(calldata), max_fee, chain_id, nonce
/// ])
/// ```
///
/// The `0` entry is the `entry_point_selector`, always zero for invoke V1.
pub fn compute_invoke_v1_hash(
    sender_address: &Felt,
    calldata: &[Felt],
    max_fee: &Felt,
    chain_id: &Felt,
    nonce: &Felt,
) -> Felt {
    let calldata_hash = hash_elements(calldata);

    hash_elements(&[
        INVOKE_PREFIX,
        VERSION_1,
        *sender_address,
        Felt::ZERO, // entry_point_selector
        calldata_hash,
        *max_fee,
        *chain_id,
        *nonce,
    ])
}

/// Compute the hash of a V1 deploy-account transaction.
///
/// Formula:
/// ```text
/// hash_elements([
///     DEPLOY_ACCOUNT_PREFIX, VERSION_1, contract_address, 0,
///     hash_elements([class_hash, salt, ...constructor_calldata]),
///     max_fee, chain_id, nonce
/// ])
/// ```
pub fn compute_deploy_account_v1_hash(
    contract_address: &Felt,
    class_hash: &Felt,
    constructor_calldata: &[Felt],
    salt: &Felt,
    max_fee: &Felt,
    chain_id: &Felt,
    nonce: &Felt,
) -> Felt {
    let mut inner = Vec::with_capacity(2 + constructor_calldata.len());
    inner.push(*class_hash);
    inner.push(*salt);
    inner.extend_from_slice(constructor_calldata);
    let inner_hash = hash_elements(&inner);

    hash_elements(&[
        DEPLOY_ACCOUNT_PREFIX,
        VERSION_1,
        *contract_address,
        Felt::ZERO, // entry_point_selector
        inner_hash,
        *max_fee,
        *chain_id,
        *nonce,
    ])
}

/// Compute the hash of a V2 declare transaction.
///
/// Formula:
/// ```text
/// hash_elements([
///     DECLARE_PREFIX, VERSION_2, sender_address, 0,
///     hash_elements([class_hash]), max_fee, chain_id, nonce,
///     compiled_class_hash
/// ])
/// ```
pub fn compute_declare_v2_hash(
    sender_address: &Felt,
    class_hash: &Felt,
    max_fee: &Felt,
    chain_id: &Felt,
    nonce: &Felt,
    compiled_class_hash: &Felt,
) -> Felt {
    let class_hash_hash = hash_elements(&[*class_hash]);

    hash_elements(&[
        DECLARE_PREFIX,
        VERSION_2,
        *sender_address,
        Felt::ZERO, // entry_point_selector
        class_hash_hash,
        *max_fee,
        *chain_id,
        *nonce,
        *compiled_class_hash,
    ])
}

// ===========================================================================
// V3 transaction hashes (Poseidon)
// ===========================================================================

/// Compute the hash of a V3 invoke transaction.
#[allow(clippy::too_many_arguments)]
pub fn compute_invoke_v3_hash(
    sender_address: &Felt,
    calldata: &[Felt],
    chain_id: &Felt,
    nonce: &Felt,
    account_deployment_data: &[Felt],
    tip: u64,
    l1_gas: &ResourceBounds,
    l2_gas: &ResourceBounds,
    l1_data_gas: &ResourceBounds,
    paymaster_data: &[Felt],
    nonce_da_mode: DaMode,
    fee_da_mode: DaMode,
) -> Felt {
    compute_invoke_v3_hash_with_proof_facts(
        sender_address,
        calldata,
        chain_id,
        nonce,
        account_deployment_data,
        tip,
        l1_gas,
        l2_gas,
        l1_data_gas,
        paymaster_data,
        nonce_da_mode,
        fee_da_mode,
        &[],
    )
}

/// Compute the hash of a V3 invoke transaction carrying optional proof facts.
///
/// `proof_facts` follows the `starknet@10.0.2` invoke-v3 preimage: when the
/// slice is non-empty, `Poseidon(proof_facts)` is appended after the calldata
/// hash. An empty slice is identical to [`compute_invoke_v3_hash`].
#[allow(clippy::too_many_arguments)]
pub fn compute_invoke_v3_hash_with_proof_facts(
    sender_address: &Felt,
    calldata: &[Felt],
    chain_id: &Felt,
    nonce: &Felt,
    account_deployment_data: &[Felt],
    tip: u64,
    l1_gas: &ResourceBounds,
    l2_gas: &ResourceBounds,
    l1_data_gas: &ResourceBounds,
    paymaster_data: &[Felt],
    nonce_da_mode: DaMode,
    fee_da_mode: DaMode,
    proof_facts: &[Felt],
) -> Felt {
    let fee_hash = compute_fee_hash(tip, l1_gas, l2_gas, l1_data_gas);
    let paymaster_hash = Poseidon::hash_array(paymaster_data);
    let da_mode = pack_da_modes(nonce_da_mode, fee_da_mode);
    let deployment_data_hash = Poseidon::hash_array(account_deployment_data);
    let calldata_hash = Poseidon::hash_array(calldata);

    let mut elements = Vec::with_capacity(10 + usize::from(!proof_facts.is_empty()));
    elements.extend_from_slice(&[
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
    ]);

    if !proof_facts.is_empty() {
        elements.push(Poseidon::hash_array(proof_facts));
    }

    Poseidon::hash_array(&elements)
}

/// Compute the hash of a V3 deploy-account transaction.
#[allow(clippy::too_many_arguments)]
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
    l1_data_gas: &ResourceBounds,
    paymaster_data: &[Felt],
    nonce_da_mode: DaMode,
    fee_da_mode: DaMode,
) -> Felt {
    let fee_hash = compute_fee_hash(tip, l1_gas, l2_gas, l1_data_gas);
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

/// Compute the hash of a V3 declare transaction.
#[allow(clippy::too_many_arguments)]
pub fn compute_declare_v3_hash(
    sender_address: &Felt,
    class_hash: &Felt,
    compiled_class_hash: &Felt,
    chain_id: &Felt,
    nonce: &Felt,
    tip: u64,
    l1_gas: &ResourceBounds,
    l2_gas: &ResourceBounds,
    l1_data_gas: &ResourceBounds,
    paymaster_data: &[Felt],
    nonce_da_mode: DaMode,
    fee_da_mode: DaMode,
    account_deployment_data: &[Felt],
) -> Felt {
    let fee_hash = compute_fee_hash(tip, l1_gas, l2_gas, l1_data_gas);
    let paymaster_hash = Poseidon::hash_array(paymaster_data);
    let da_mode = pack_da_modes(nonce_da_mode, fee_da_mode);
    let deployment_data_hash = Poseidon::hash_array(account_deployment_data);
    let calldata_hash = Poseidon::hash_array(&[]); // empty for declare

    Poseidon::hash_array(&[
        DECLARE_PREFIX,
        VERSION_3,
        *sender_address,
        fee_hash,
        paymaster_hash,
        *chain_id,
        *nonce,
        da_mode,
        deployment_data_hash,
        calldata_hash,
        *class_hash,
        *compiled_class_hash,
    ])
}

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Compute the fee-related Poseidon hash: `h(tip, l1_gas_bounds, l2_gas_bounds, l1_data_gas_bounds)`.
fn compute_fee_hash(
    tip: u64,
    l1_gas: &ResourceBounds,
    l2_gas: &ResourceBounds,
    l1_data_gas: &ResourceBounds,
) -> Felt {
    let l1_packed = pack_resource_bounds(&L1_GAS_NAME, l1_gas);
    let l2_packed = pack_resource_bounds(&L2_GAS_NAME, l2_gas);
    let l1_data_packed = pack_resource_bounds(&L1_DATA_NAME, l1_data_gas);
    Poseidon::hash_array(&[
        Felt::from(tip as u128),
        l1_packed,
        l2_packed,
        l1_data_packed,
    ])
}

/// Pack resource bounds into a single Felt:
/// `resource_name * 2^192 + max_amount * 2^128 + max_price_per_unit`
fn pack_resource_bounds(resource_name: &Felt, bounds: &ResourceBounds) -> Felt {
    *resource_name * TWO_POW_192
        + Felt::from(bounds.max_amount as u128) * TWO_POW_128
        + Felt::from(bounds.max_price_per_unit)
}

/// Pack data availability modes into a single Felt:
/// `(nonce_da_mode << 32) + fee_da_mode`
fn pack_da_modes(nonce_da: DaMode, fee_da: DaMode) -> Felt {
    Felt::from(((nonce_da as u64) << 32) + fee_da as u64)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Shared test constants
    const SN_SEPOLIA: Felt = Felt::from_hex_unchecked("0x534e5f5345504f4c4941");

    // -----------------------------------------------------------------------
    // V1 Invoke
    // -----------------------------------------------------------------------

    #[test]
    fn test_invoke_v1_hash_deterministic() {
        let sender = Felt::from_hex_unchecked("0x123");
        let calldata = vec![Felt::from_hex_unchecked("0x456")];
        let max_fee = Felt::from_hex_unchecked("0x1000");
        let nonce = Felt::ZERO;

        let h1 = compute_invoke_v1_hash(&sender, &calldata, &max_fee, &SN_SEPOLIA, &nonce);
        let h2 = compute_invoke_v1_hash(&sender, &calldata, &max_fee, &SN_SEPOLIA, &nonce);

        assert_eq!(h1, h2);
        assert_ne!(h1, Felt::ZERO);
    }

    #[test]
    fn test_invoke_v1_hash_different_inputs() {
        let calldata = vec![Felt::ONE];
        let max_fee = Felt::from_hex_unchecked("0x1000");
        let nonce = Felt::ZERO;

        let h1 = compute_invoke_v1_hash(
            &Felt::from_hex_unchecked("0x111"),
            &calldata,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
        );
        let h2 = compute_invoke_v1_hash(
            &Felt::from_hex_unchecked("0x222"),
            &calldata,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
        );

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_invoke_v1_different_nonce() {
        let sender = Felt::from_hex_unchecked("0x123");
        let calldata = vec![Felt::ONE];
        let max_fee = Felt::from_hex_unchecked("0x1000");

        let h1 = compute_invoke_v1_hash(&sender, &calldata, &max_fee, &SN_SEPOLIA, &Felt::ZERO);
        let h2 = compute_invoke_v1_hash(&sender, &calldata, &max_fee, &SN_SEPOLIA, &Felt::ONE);

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_invoke_v1_different_max_fee() {
        let sender = Felt::from_hex_unchecked("0x123");
        let calldata = vec![Felt::ONE];
        let nonce = Felt::ZERO;

        let h1 = compute_invoke_v1_hash(
            &sender,
            &calldata,
            &Felt::from_hex_unchecked("0x1000"),
            &SN_SEPOLIA,
            &nonce,
        );
        let h2 = compute_invoke_v1_hash(
            &sender,
            &calldata,
            &Felt::from_hex_unchecked("0x2000"),
            &SN_SEPOLIA,
            &nonce,
        );

        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // V1 Deploy Account
    // -----------------------------------------------------------------------

    #[test]
    fn test_deploy_account_v1_hash_deterministic() {
        let address = Felt::from_hex_unchecked("0xABC");
        let class_hash = Felt::from_hex_unchecked("0xDEF");
        let calldata = vec![Felt::ONE, Felt::TWO];
        let salt = Felt::from_hex_unchecked("0x999");
        let max_fee = Felt::from_hex_unchecked("0x5000");
        let nonce = Felt::ZERO;

        let h1 = compute_deploy_account_v1_hash(
            &address,
            &class_hash,
            &calldata,
            &salt,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
        );
        let h2 = compute_deploy_account_v1_hash(
            &address,
            &class_hash,
            &calldata,
            &salt,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
        );

        assert_eq!(h1, h2);
        assert_ne!(h1, Felt::ZERO);
    }

    #[test]
    fn test_deploy_account_v1_different_class_hash() {
        let address = Felt::from_hex_unchecked("0xABC");
        let calldata = vec![Felt::ONE];
        let salt = Felt::from_hex_unchecked("0x999");
        let max_fee = Felt::from_hex_unchecked("0x5000");
        let nonce = Felt::ZERO;

        let h1 = compute_deploy_account_v1_hash(
            &address,
            &Felt::from_hex_unchecked("0xDEF"),
            &calldata,
            &salt,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
        );
        let h2 = compute_deploy_account_v1_hash(
            &address,
            &Felt::from_hex_unchecked("0xFED"),
            &calldata,
            &salt,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
        );

        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // V2 Declare
    // -----------------------------------------------------------------------

    #[test]
    fn test_declare_v2_hash_deterministic() {
        let sender = Felt::from_hex_unchecked("0x123");
        let class_hash = Felt::from_hex_unchecked("0x456");
        let max_fee = Felt::from_hex_unchecked("0x1000");
        let nonce = Felt::ZERO;
        let compiled = Felt::from_hex_unchecked("0x789");

        let h1 = compute_declare_v2_hash(
            &sender,
            &class_hash,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
            &compiled,
        );
        let h2 = compute_declare_v2_hash(
            &sender,
            &class_hash,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
            &compiled,
        );

        assert_eq!(h1, h2);
        assert_ne!(h1, Felt::ZERO);
    }

    #[test]
    fn test_declare_v2_different_compiled_class_hash() {
        let sender = Felt::from_hex_unchecked("0x123");
        let class_hash = Felt::from_hex_unchecked("0x456");
        let max_fee = Felt::from_hex_unchecked("0x1000");
        let nonce = Felt::ZERO;

        let h1 = compute_declare_v2_hash(
            &sender,
            &class_hash,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
            &Felt::from_hex_unchecked("0x789"),
        );
        let h2 = compute_declare_v2_hash(
            &sender,
            &class_hash,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
            &Felt::from_hex_unchecked("0xABC"),
        );

        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // V1: invoke != deploy != declare for same address
    // -----------------------------------------------------------------------

    #[test]
    fn test_v1_invoke_deploy_declare_differ() {
        let address = Felt::from_hex_unchecked("0x123");
        let class_hash = Felt::from_hex_unchecked("0x456");
        let calldata = vec![Felt::ONE];
        let max_fee = Felt::from_hex_unchecked("0x1000");
        let nonce = Felt::ZERO;

        let invoke_hash =
            compute_invoke_v1_hash(&address, &calldata, &max_fee, &SN_SEPOLIA, &nonce);

        let deploy_hash = compute_deploy_account_v1_hash(
            &address,
            &class_hash,
            &calldata,
            &Felt::ZERO,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
        );

        let declare_hash = compute_declare_v2_hash(
            &address,
            &class_hash,
            &max_fee,
            &SN_SEPOLIA,
            &nonce,
            &Felt::from_hex_unchecked("0x789"),
        );

        assert_ne!(invoke_hash, deploy_hash);
        assert_ne!(invoke_hash, declare_hash);
        assert_ne!(deploy_hash, declare_hash);
    }

    // -----------------------------------------------------------------------
    // V3 Invoke
    // -----------------------------------------------------------------------

    #[test]
    fn test_invoke_v3_hash_deterministic() {
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

        let h1 = compute_invoke_v3_hash(
            &sender,
            &calldata,
            &SN_SEPOLIA,
            &nonce,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );
        let h2 = compute_invoke_v3_hash(
            &sender,
            &calldata,
            &SN_SEPOLIA,
            &nonce,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        assert_eq!(h1, h2);
        assert_ne!(h1, Felt::ZERO);
    }

    #[test]
    fn test_invoke_v3_hash_different_inputs() {
        let l1_gas = ResourceBounds {
            max_amount: 1000,
            max_price_per_unit: 1_000_000,
        };
        let l2_gas = ResourceBounds::zero();

        let h1 = compute_invoke_v3_hash(
            &Felt::from_hex_unchecked("0x111"),
            &[Felt::ONE],
            &SN_SEPOLIA,
            &Felt::ZERO,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );
        let h2 = compute_invoke_v3_hash(
            &Felt::from_hex_unchecked("0x222"),
            &[Felt::ONE],
            &SN_SEPOLIA,
            &Felt::ZERO,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_invoke_v3_empty_proof_facts_matches_non_proof_hash() {
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

        let without_proof = compute_invoke_v3_hash(
            &sender,
            &calldata,
            &SN_SEPOLIA,
            &nonce,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );
        let empty_proof = compute_invoke_v3_hash_with_proof_facts(
            &sender,
            &calldata,
            &SN_SEPOLIA,
            &nonce,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
            &[],
        );

        assert_eq!(without_proof, empty_proof);
    }

    #[test]
    fn test_invoke_v3_non_empty_proof_facts_change_hash() {
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
        let proof_facts = vec![
            Felt::from_hex_unchecked("0xabc"),
            Felt::from_hex_unchecked("0xdef"),
        ];

        let without_proof = compute_invoke_v3_hash(
            &sender,
            &calldata,
            &SN_SEPOLIA,
            &nonce,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );
        let with_proof = compute_invoke_v3_hash_with_proof_facts(
            &sender,
            &calldata,
            &SN_SEPOLIA,
            &nonce,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
            &proof_facts,
        );

        assert_ne!(without_proof, with_proof);
        assert_ne!(with_proof, Felt::ZERO);
    }

    // -----------------------------------------------------------------------
    // V3 Deploy Account
    // -----------------------------------------------------------------------

    #[test]
    fn test_deploy_account_v3_hash_deterministic() {
        let address = Felt::from_hex_unchecked("0xABC");
        let class_hash = Felt::from_hex_unchecked("0xDEF");
        let calldata = vec![Felt::ONE, Felt::TWO];
        let salt = Felt::from_hex_unchecked("0x999");
        let l1_gas = ResourceBounds {
            max_amount: 500,
            max_price_per_unit: 100_000,
        };
        let l2_gas = ResourceBounds::zero();

        let h1 = compute_deploy_account_v3_hash(
            &address,
            &class_hash,
            &calldata,
            &salt,
            &SN_SEPOLIA,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );
        let h2 = compute_deploy_account_v3_hash(
            &address,
            &class_hash,
            &calldata,
            &salt,
            &SN_SEPOLIA,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        assert_eq!(h1, h2);
        assert_ne!(h1, Felt::ZERO);
    }

    // -----------------------------------------------------------------------
    // V3 Declare
    // -----------------------------------------------------------------------

    #[test]
    fn test_declare_v3_hash_deterministic() {
        let sender = Felt::from_hex_unchecked("0x123");
        let class_hash = Felt::from_hex_unchecked("0x456");
        let compiled = Felt::from_hex_unchecked("0x789");
        let l1_gas = ResourceBounds {
            max_amount: 1000,
            max_price_per_unit: 1_000_000,
        };
        let l2_gas = ResourceBounds::zero();

        let h1 = compute_declare_v3_hash(
            &sender,
            &class_hash,
            &compiled,
            &SN_SEPOLIA,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
            &[],
        );
        let h2 = compute_declare_v3_hash(
            &sender,
            &class_hash,
            &compiled,
            &SN_SEPOLIA,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
            &[],
        );

        assert_eq!(h1, h2);
        assert_ne!(h1, Felt::ZERO);
    }

    #[test]
    fn test_declare_v3_different_compiled_class() {
        let sender = Felt::from_hex_unchecked("0x123");
        let class_hash = Felt::from_hex_unchecked("0x456");
        let l1_gas = ResourceBounds {
            max_amount: 1000,
            max_price_per_unit: 1_000_000,
        };
        let l2_gas = ResourceBounds::zero();

        let h1 = compute_declare_v3_hash(
            &sender,
            &class_hash,
            &Felt::from_hex_unchecked("0x789"),
            &SN_SEPOLIA,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
            &[],
        );
        let h2 = compute_declare_v3_hash(
            &sender,
            &class_hash,
            &Felt::from_hex_unchecked("0xABC"),
            &SN_SEPOLIA,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
            &[],
        );

        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // V3: invoke != deploy != declare
    // -----------------------------------------------------------------------

    #[test]
    fn test_v3_invoke_deploy_declare_differ() {
        let address = Felt::from_hex_unchecked("0x123");
        let class_hash = Felt::from_hex_unchecked("0x456");
        let compiled = Felt::from_hex_unchecked("0x789");
        let calldata = vec![Felt::ONE];
        let l1_gas = ResourceBounds {
            max_amount: 100,
            max_price_per_unit: 100,
        };
        let l2_gas = ResourceBounds::zero();

        let invoke_hash = compute_invoke_v3_hash(
            &address,
            &calldata,
            &SN_SEPOLIA,
            &Felt::ZERO,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        let deploy_hash = compute_deploy_account_v3_hash(
            &address,
            &class_hash,
            &calldata,
            &Felt::ZERO,
            &SN_SEPOLIA,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        let declare_hash = compute_declare_v3_hash(
            &address,
            &class_hash,
            &compiled,
            &SN_SEPOLIA,
            &Felt::ZERO,
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
            &[],
        );

        assert_ne!(invoke_hash, deploy_hash);
        assert_ne!(invoke_hash, declare_hash);
        assert_ne!(deploy_hash, declare_hash);
    }

    // -----------------------------------------------------------------------
    // Packing helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_resource_bounds_packing() {
        let packed = pack_resource_bounds(&L1_GAS_NAME, &ResourceBounds::zero());
        assert_ne!(packed, Felt::ZERO);

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
    fn test_resource_bounds_packing_injective() {
        let a = pack_resource_bounds(
            &L1_GAS_NAME,
            &ResourceBounds {
                max_amount: 0,
                max_price_per_unit: 1u128 << 64,
            },
        );
        let b = pack_resource_bounds(
            &L1_GAS_NAME,
            &ResourceBounds {
                max_amount: 1,
                max_price_per_unit: 0,
            },
        );
        assert_ne!(a, b, "packing must be injective");
    }

    #[test]
    fn test_resource_bounds_packing_layout() {
        let packed = pack_resource_bounds(
            &Felt::ZERO,
            &ResourceBounds {
                max_amount: 1,
                max_price_per_unit: 0,
            },
        );
        assert_eq!(packed, TWO_POW_128, "max_amount=1 should land at bit 128");
    }

    #[test]
    fn test_da_mode_packing() {
        let l1_l1 = pack_da_modes(DaMode::L1, DaMode::L1);
        assert_eq!(l1_l1, Felt::ZERO);

        let l1_l2 = pack_da_modes(DaMode::L1, DaMode::L2);
        assert_eq!(l1_l2, Felt::ONE);

        let l2_l1 = pack_da_modes(DaMode::L2, DaMode::L1);
        assert_eq!(l2_l1, Felt::from(4294967296u64)); // 2^32
    }

    // -----------------------------------------------------------------------
    // Cross-version: V1 invoke != V3 invoke for same logical tx
    // -----------------------------------------------------------------------

    #[test]
    fn test_v1_v3_invoke_differ() {
        let sender = Felt::from_hex_unchecked("0x123");
        let calldata = vec![Felt::ONE];
        let nonce = Felt::ZERO;

        let v1 = compute_invoke_v1_hash(
            &sender,
            &calldata,
            &Felt::from_hex_unchecked("0x1000"),
            &SN_SEPOLIA,
            &nonce,
        );

        let l1_gas = ResourceBounds {
            max_amount: 100,
            max_price_per_unit: 100,
        };
        let l2_gas = ResourceBounds::zero();

        let v3 = compute_invoke_v3_hash(
            &sender,
            &calldata,
            &SN_SEPOLIA,
            &nonce,
            &[],
            0,
            &l1_gas,
            &l2_gas,
            &ResourceBounds::zero(),
            &[],
            DaMode::L1,
            DaMode::L1,
        );

        assert_ne!(v1, v3);
    }
}
