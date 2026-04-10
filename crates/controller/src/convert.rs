//! Type conversion layer between `starknet_rust` 0.18 (ours) and `starknet` 0.17 (account_sdk).
//!
//! Both crates re-export `starknet-types-core 0.2.x` but Rust treats them as distinct types.
//! We bridge via `Felt::to_bytes_be()` / `Felt::from_bytes_be()` byte roundtrips.

use starknet_rust::core::types as our;
use starknet_types_core::felt::Felt as CoreFelt;

/// `starknet` 0.17 types used by `account_sdk`.
pub(crate) mod sdk {
    pub use starknet::core::types::Call;
    pub use starknet::core::types::FeeEstimate;
    pub use starknet::core::types::Felt;
}

// ---------------------------------------------------------------------------
// Felt conversion
// ---------------------------------------------------------------------------

/// Convert our Felt (`starknet-rust 0.18`) to the SDK Felt (`starknet 0.17`).
#[inline]
pub fn felt_ours_to_sdk(f: our::Felt) -> sdk::Felt {
    sdk::Felt::from_bytes_be(&f.to_bytes_be())
}

/// Convert the SDK Felt (`starknet 0.17`) to our Felt (`starknet-rust 0.18`).
#[inline]
pub fn felt_sdk_to_ours(f: sdk::Felt) -> our::Felt {
    our::Felt::from_bytes_be(&f.to_bytes_be())
}

/// Convert a `starknet-types-core` felt to our `starknet-rust` felt.
#[inline]
pub fn felt_core_to_ours(f: CoreFelt) -> our::Felt {
    our::Felt::from_bytes_be(&f.to_bytes_be())
}

// ---------------------------------------------------------------------------
// Call conversion
// ---------------------------------------------------------------------------

/// Convert one of our `Call`s to the SDK `Call` used by `account_sdk`.
pub fn call_to_sdk(c: &our::Call) -> sdk::Call {
    sdk::Call {
        to: felt_ours_to_sdk(c.to),
        selector: felt_ours_to_sdk(c.selector),
        calldata: c.calldata.iter().copied().map(felt_ours_to_sdk).collect(),
    }
}

// ---------------------------------------------------------------------------
// FeeEstimate conversion
// ---------------------------------------------------------------------------

/// Convert an SDK `FeeEstimate` to our `FeeEstimate`.
///
/// Both types have identical field layouts (all `u64` / `u128` primitives), so
/// this is a direct field-by-field copy with no Felt conversion needed.
pub fn fee_estimate_to_ours(f: &sdk::FeeEstimate) -> our::FeeEstimate {
    our::FeeEstimate {
        l1_gas_consumed: f.l1_gas_consumed,
        l1_gas_price: f.l1_gas_price,
        l2_gas_consumed: f.l2_gas_consumed,
        l2_gas_price: f.l2_gas_price,
        l1_data_gas_consumed: f.l1_data_gas_consumed,
        l1_data_gas_price: f.l1_data_gas_price,
        overall_fee: f.overall_fee,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn felt_roundtrip() {
        let original = our::Felt::from(0xDEADBEEFu64);
        let sdk = felt_ours_to_sdk(original);
        let back = felt_sdk_to_ours(sdk);
        assert_eq!(original, back);
    }

    #[test]
    fn felt_zero_roundtrip() {
        let zero = our::Felt::ZERO;
        assert_eq!(zero, felt_sdk_to_ours(felt_ours_to_sdk(zero)));
    }

    #[test]
    fn call_roundtrip() {
        let call = our::Call {
            to: our::Felt::from(0x123u64),
            selector: our::Felt::from(0x456u64),
            calldata: vec![our::Felt::from(1u64), our::Felt::from(2u64)],
        };
        let sdk_call = call_to_sdk(&call);
        assert_eq!(felt_sdk_to_ours(sdk_call.to), call.to);
        assert_eq!(felt_sdk_to_ours(sdk_call.selector), call.selector);
        assert_eq!(sdk_call.calldata.len(), 2);
        assert_eq!(felt_sdk_to_ours(sdk_call.calldata[0]), call.calldata[0]);
        assert_eq!(felt_sdk_to_ours(sdk_call.calldata[1]), call.calldata[1]);
    }

    #[test]
    fn fee_estimate_field_copy() {
        let sdk_est = sdk::FeeEstimate {
            l1_gas_consumed: 100,
            l1_gas_price: 200,
            l2_gas_consumed: 300,
            l2_gas_price: 400,
            l1_data_gas_consumed: 500,
            l1_data_gas_price: 600,
            overall_fee: 42000,
        };
        let ours = fee_estimate_to_ours(&sdk_est);
        assert_eq!(ours.l1_gas_consumed, 100);
        assert_eq!(ours.l1_gas_price, 200);
        assert_eq!(ours.l2_gas_consumed, 300);
        assert_eq!(ours.l2_gas_price, 400);
        assert_eq!(ours.l1_data_gas_consumed, 500);
        assert_eq!(ours.l1_data_gas_price, 600);
        assert_eq!(ours.overall_fee, 42000);
    }
}
