//! The input-aware unlocking budget: `T` must leave room for every input's
//! scriptSig and witness under the standard weight.

use super::*;

/// A valid `T` with `inputs` distinct inputs and one `OP_1` output.
fn transaction(inputs: usize) -> Vec<u8> {
    let mut transaction = vec![2, 0, 0, 0];
    compact_size(&mut transaction, inputs);
    for input in 0..inputs {
        let mut txid = [0x11; 32];
        txid[..8].copy_from_slice(&(input as u64).to_le_bytes());
        transaction.extend_from_slice(&txid);
        transaction.extend_from_slice(&[0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    }
    transaction.extend_from_slice(&[1, 0xe8, 3, 0, 0, 0, 0, 0, 0, 1, 0x51, 0, 0, 0, 0]);
    transaction
}

fn compact_size(out: &mut Vec<u8>, value: usize) {
    match u16::try_from(value) {
        Ok(small) if small < 0xfd => out.push(small as u8),
        Ok(medium) => {
            out.push(0xfd);
            out.extend_from_slice(&medium.to_le_bytes());
        }
        Err(_) => panic!("test transactions stay under 65536 inputs"),
    }
}

fn worst_weight(inputs: usize) -> usize {
    WITNESS_SCALE_FACTOR * transaction(inputs).len()
        + SEGWIT_MARKER_AND_FLAG
        + inputs * MAX_UNLOCKING_WEIGHT_PER_INPUT
}

#[test]
fn derived_budget_is_pinned() {
    assert_eq!(MAX_P2WPKH_WITNESS, 109);
    assert_eq!(MAX_UNLOCKING_WEIGHT_PER_INPUT, 40_117);
}

#[test]
fn the_most_inputs_that_fit_are_accepted_and_one_more_is_refused() {
    let most = (1..)
        .take_while(|&inputs| worst_weight(inputs) <= MAX_STANDARD_TX_WEIGHT)
        .last()
        .unwrap();
    assert_eq!(most, 9, "derived from the constants above");
    validate(&transaction(most)).unwrap();
    let error = validate(&transaction(most + 1)).unwrap_err().to_string();
    assert!(
        error.contains("T leaves no room for its inputs' unlocking data"),
        "{error}"
    );
}

#[test]
fn many_inputs_are_refused_far_under_the_byte_cap() {
    let inputs = 50;
    let transaction = transaction(inputs);
    assert!(transaction.len() * 20 < MAX_TRANSACTION_SIZE);
    let error = validate(&transaction).unwrap_err().to_string();
    assert!(
        error.contains(&format!("{inputs} inputs signed could weigh more than the")),
        "{error}"
    );
}

#[test]
fn a_two_input_withdrawal_fits_easily() {
    assert!(worst_weight(2) < MAX_STANDARD_TX_WEIGHT / 4);
    validate(&transaction(2)).unwrap();
}

#[test]
fn a_t_at_the_byte_cap_still_has_room_for_four_inputs() {
    let at_cap = WITNESS_SCALE_FACTOR * MAX_TRANSACTION_SIZE + SEGWIT_MARKER_AND_FLAG;
    let room = (MAX_STANDARD_TX_WEIGHT - at_cap) / MAX_UNLOCKING_WEIGHT_PER_INPUT;
    assert_eq!(room, 4, "derived from the constants above");
}
