mod codec;
mod contract;
mod coordinators;

use super::MultisigCall;
use krusty_kms_common::Address;
use starknet_types_core::felt::Felt;

fn address(value: u64) -> Address {
    Address::from(Felt::from(value))
}

fn call() -> MultisigCall {
    MultisigCall::new(
        address(0xabc),
        Felt::from(0x123u64),
        vec![Felt::from(7u64), Felt::from(8u64)],
    )
}
