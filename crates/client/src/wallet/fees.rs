//! Turning a fee estimate into pinned V3 transaction bounds.
//!
//! Kept beside the submit paths rather than inside them: the conversion is
//! mechanical, and separating it keeps the order a reader must follow —
//! nonce, bounds, prepare, sign — visible in one screen.

use krusty_kms_common::fee::{FeeEstimateInput, ResolvedFeeBounds};

/// Convert a provider fee estimate into the Starknet-free shape `FeeBounds` takes.
pub(crate) fn estimate_input(
    estimate: &starknet_rust::core::types::FeeEstimate,
) -> FeeEstimateInput {
    FeeEstimateInput {
        l1_gas_consumed: estimate.l1_gas_consumed,
        l1_gas_price: estimate.l1_gas_price,
        l2_gas_consumed: estimate.l2_gas_consumed,
        l2_gas_price: estimate.l2_gas_price,
        l1_data_gas_consumed: estimate.l1_data_gas_consumed,
        l1_data_gas_price: estimate.l1_data_gas_price,
    }
}

/// Pin every fee field on an execution builder so none is filled from RPC.
pub(super) fn apply_bounds<'a, A>(
    execution: starknet_rust::accounts::ExecutionV3<'a, A>,
    bounds: &ResolvedFeeBounds,
) -> starknet_rust::accounts::ExecutionV3<'a, A> {
    execution
        .l1_gas(bounds.l1_gas)
        .l1_gas_price(bounds.l1_gas_price)
        .l2_gas(bounds.l2_gas)
        .l2_gas_price(bounds.l2_gas_price)
        .l1_data_gas(bounds.l1_data_gas)
        .l1_data_gas_price(bounds.l1_data_gas_price)
        .tip(bounds.tip)
}
