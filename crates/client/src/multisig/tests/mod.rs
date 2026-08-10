mod codec;
mod contract;
mod coordinators;
mod envelope;

use super::{MultisigCall, MultisigCoordinationMessage, MultisigSignerNotice};
use crate::wallet::utils::core_felt_to_rs;
use krusty_kms_common::{Address, ChainId};
use starknet_rust::signers::SigningKey;
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

fn confirmation_notice(signer: u64) -> MultisigCoordinationMessage {
    MultisigCoordinationMessage::Confirmation(MultisigSignerNotice::new(
        address(1),
        ChainId::Sepolia,
        Felt::from(42u64),
        address(signer),
    ))
}

fn test_signing_key(secret: u64) -> SigningKey {
    SigningKey::from_secret_scalar(core_felt_to_rs(Felt::from(secret)))
}
