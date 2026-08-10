//! Transaction hashing and Cairo calldata encode/decode for the multisig ABI.

use super::types::{MultisigCall, MultisigTransactionState};
use super::StarknetRsFelt;
use crate::wallet::utils::{core_felt_to_rs, rs_felt_to_core};
use krusty_kms_common::{Address, KmsError, Result};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};

/// Compute the OpenZeppelin multisig transaction ID for one call.
#[must_use]
pub fn hash_transaction(call: &MultisigCall, salt: Felt) -> Felt {
    hash_transaction_batch(std::slice::from_ref(call), salt)
}

/// Compute the OpenZeppelin multisig transaction ID for a batch of calls.
///
/// This mirrors `PedersenTrait::new(0).update_with(calls).update_with(salt)`
/// and the `Hash<Call>` implementation in OpenZeppelin Cairo contracts:
/// `[calls_len, to, selector, calldata_len, calldata..., salt]`.
#[must_use]
pub fn hash_transaction_batch(calls: &[MultisigCall], salt: Felt) -> Felt {
    let mut state = Felt::ZERO;
    state = pedersen_update(state, Felt::from(calls.len() as u64));
    for call in calls {
        state = pedersen_update(state, call.to.as_felt());
        state = pedersen_update(state, call.selector);
        state = pedersen_update(state, Felt::from(call.calldata.len() as u64));
        for value in &call.calldata {
            state = pedersen_update(state, *value);
        }
    }
    pedersen_update(state, salt)
}

fn pedersen_update(state: Felt, value: Felt) -> Felt {
    Pedersen::hash(&state, &value)
}

pub(super) fn serialize_single_call_args(call: &MultisigCall, salt: Felt) -> Vec<StarknetRsFelt> {
    let mut calldata = Vec::with_capacity(call.calldata.len() + 4);
    calldata.push(core_felt_to_rs(call.to.as_felt()));
    calldata.push(core_felt_to_rs(call.selector));
    calldata.push(core_felt_to_rs(Felt::from(call.calldata.len() as u64)));
    calldata.extend(call.calldata.iter().copied().map(core_felt_to_rs));
    calldata.push(core_felt_to_rs(salt));
    calldata
}

pub(super) fn serialize_batch_call_args(calls: &[MultisigCall], salt: Felt) -> Vec<StarknetRsFelt> {
    let mut calldata = serialize_call_span(calls);
    calldata.push(core_felt_to_rs(salt));
    calldata
}

fn serialize_call_span(calls: &[MultisigCall]) -> Vec<StarknetRsFelt> {
    let calldata_len = calls.iter().map(|call| call.calldata.len()).sum::<usize>();
    let mut calldata = Vec::with_capacity(1 + calls.len() * 3 + calldata_len);
    calldata.push(core_felt_to_rs(Felt::from(calls.len() as u64)));
    for call in calls {
        calldata.push(core_felt_to_rs(call.to.as_felt()));
        calldata.push(core_felt_to_rs(call.selector));
        calldata.push(core_felt_to_rs(Felt::from(call.calldata.len() as u64)));
        calldata.extend(call.calldata.iter().copied().map(core_felt_to_rs));
    }
    calldata
}

pub(super) fn serialize_quorum_and_signers(new_quorum: u32, signers: &[Address]) -> Vec<StarknetRsFelt> {
    let mut calldata = Vec::with_capacity(signers.len() + 2);
    calldata.push(core_felt_to_rs(Felt::from(new_quorum)));
    calldata.push(core_felt_to_rs(Felt::from(signers.len() as u64)));
    calldata.extend(
        signers
            .iter()
            .map(|signer| core_felt_to_rs(signer.as_felt())),
    );
    calldata
}

pub(super) fn read_felt(result: &[StarknetRsFelt], name: &str) -> Result<Felt> {
    result
        .first()
        .copied()
        .map(rs_felt_to_core)
        .ok_or_else(|| KmsError::DeserializationError(format!("empty response from {name}")))
}

pub(super) fn read_bool(result: &[StarknetRsFelt], name: &str) -> Result<bool> {
    Ok(read_felt(result, name)? != Felt::ZERO)
}

pub(super) fn read_u32(result: &[StarknetRsFelt], name: &str) -> Result<u32> {
    let bytes = read_felt(result, name)?.to_bytes_be();
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[28..32]);
    Ok(u32::from_be_bytes(value))
}

pub(super) fn read_u64(result: &[StarknetRsFelt], name: &str) -> Result<u64> {
    let bytes = read_felt(result, name)?.to_bytes_be();
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[24..32]);
    Ok(u64::from_be_bytes(value))
}

fn read_usize(result: &StarknetRsFelt, name: &str) -> Result<usize> {
    let bytes = rs_felt_to_core(*result).to_bytes_be();
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[24..32]);
    usize::try_from(u64::from_be_bytes(value)).map_err(|error| {
        KmsError::DeserializationError(format!("invalid usize response from {name}: {error}"))
    })
}

pub(super) fn read_address_span(result: &[StarknetRsFelt], name: &str) -> Result<Vec<Address>> {
    let Some(first) = result.first() else {
        return Err(KmsError::DeserializationError(format!(
            "empty response from {name}"
        )));
    };

    let count = read_usize(first, name)?;
    if result.len() != count + 1 {
        return Err(KmsError::DeserializationError(format!(
            "unexpected {name} response length: expected {}, got {}",
            count + 1,
            result.len()
        )));
    }

    Ok(result[1..]
        .iter()
        .copied()
        .map(rs_felt_to_core)
        .map(Address::from)
        .collect())
}

pub(super) fn read_transaction_state(result: &[StarknetRsFelt]) -> Result<MultisigTransactionState> {
    match read_u32(result, "get_transaction_state")? {
        0 => Ok(MultisigTransactionState::NotFound),
        1 => Ok(MultisigTransactionState::Pending),
        2 => Ok(MultisigTransactionState::Confirmed),
        3 => Ok(MultisigTransactionState::Executed),
        value => Err(KmsError::DeserializationError(format!(
            "unknown multisig transaction state {value}"
        ))),
    }
}
