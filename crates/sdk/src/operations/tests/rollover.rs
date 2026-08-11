use super::super::{rollover, RolloverParams};
use super::support::create_test_account;
use starknet_types_core::felt::Felt;

#[test]
fn test_rollover() {
    let mut account = create_test_account();
    account.set_pending_balance(50);

    let params = RolloverParams {
        nonce: Felt::from(1u64),
        chain_id: Felt::from(1u64),
        tongo_address: Felt::from(123u64),
        sender_address: Felt::from(0xCAFEu64),
    };

    let result = rollover(&account, params);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().pending_amount, 50);
}

#[test]
fn test_rollover_zero_pending() {
    let mut account = create_test_account();
    account.set_pending_balance(0);

    let params = RolloverParams {
        nonce: Felt::from(1u64),
        chain_id: Felt::from(1u64),
        tongo_address: Felt::from(123u64),
        sender_address: Felt::from(0xCAFEu64),
    };

    let result = rollover(&account, params);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().pending_amount, 0);
}
