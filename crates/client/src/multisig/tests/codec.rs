//! Calldata serialization, transaction hashing, and proposal JSON encoding.

use super::{address, call};
use crate::multisig::codec::{serialize_batch_call_args, serialize_single_call_args};
use crate::multisig::{hash_transaction, MultisigCall, MultisigProposal};
use crate::wallet::utils::rs_felt_to_core;
use krusty_kms_common::ChainId;
use starknet_types_core::felt::Felt;

#[test]
fn test_single_call_calldata_serialization() {
    let encoded = serialize_single_call_args(&call(), Felt::from(99u64));
    let decoded = encoded.into_iter().map(rs_felt_to_core).collect::<Vec<_>>();
    assert_eq!(
        decoded,
        vec![
            Felt::from(0xabcu64),
            Felt::from(0x123u64),
            Felt::from(2u64),
            Felt::from(7u64),
            Felt::from(8u64),
            Felt::from(99u64),
        ]
    );
}

#[test]
fn test_batch_call_calldata_serialization() {
    let calls = vec![
        call(),
        MultisigCall::new(address(0xdef), Felt::from(0x456u64), vec![]),
    ];
    let encoded = serialize_batch_call_args(&calls, Felt::from(99u64));
    let decoded = encoded.into_iter().map(rs_felt_to_core).collect::<Vec<_>>();
    assert_eq!(
        decoded,
        vec![
            Felt::from(2u64),
            Felt::from(0xabcu64),
            Felt::from(0x123u64),
            Felt::from(2u64),
            Felt::from(7u64),
            Felt::from(8u64),
            Felt::from(0xdefu64),
            Felt::from(0x456u64),
            Felt::from(0u64),
            Felt::from(99u64),
        ]
    );
}

#[test]
fn test_transaction_hash_changes_with_salt() {
    let call = call();
    let first = hash_transaction(&call, Felt::from(1u64));
    let second = hash_transaction(&call, Felt::from(2u64));
    assert_ne!(first, second);
}

#[test]
fn test_proposal_json_uses_hex_felts() {
    let proposal = MultisigProposal::new(
        address(1),
        ChainId::Sepolia,
        vec![call()],
        Felt::from(99u64),
        address(2),
        Some("rotate signer".to_string()),
    );
    let json = serde_json::to_string(&proposal).unwrap();
    assert!(json.contains("0x0000000000000000000000000000000000000000000000000000000000000063"));
    let roundtrip: MultisigProposal = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip, proposal);
    roundtrip.validate_transaction_id().unwrap();
}
