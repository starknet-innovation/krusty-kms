use super::super::{withdraw, WithdrawParams};
use super::support::{create_test_account, encrypt_balance_for_account};
use krusty_kms_common::ElGamalCiphertext;
use starknet_types_core::felt::Felt;

#[test]
#[ignore = "Comprehensive testing done in integration tests"]
fn test_withdraw() {
    // Note: This test is simplified. Comprehensive withdraw testing
    // is performed in integration tests with real on-chain state.
    let mut account = create_test_account();
    account.set_balance(1000); // Set balance to match cipher
    let current_balance = encrypt_balance_for_account(&account, 1000, Felt::from(42u64));

    let params = WithdrawParams {
        recipient_address: Felt::from(999u64),
        amount: 100,
        nonce: Felt::from(1u64),
        chain_id: Felt::from(1u64),
        tongo_address: Felt::from(123u64),
        sender_address: Felt::from(0xCAFEu64),
        current_balance,
        bit_size: 32,

        auditor_key: None,
    };

    let result = withdraw(&account, params);
    assert!(result.is_ok());
}

#[test]
fn test_withdraw_insufficient_balance() {
    use krusty_kms_crypto::StarkCurve;
    let account = create_test_account();
    let g = StarkCurve::generator();
    let current_balance = ElGamalCiphertext {
        l: StarkCurve::mul(&Felt::from(100u128), Some(&g)),
        r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
    };

    let params = WithdrawParams {
        recipient_address: Felt::from(999u64),
        amount: 2000,
        nonce: Felt::from(1u64),
        chain_id: Felt::from(1u64),
        tongo_address: Felt::from(123u64),
        sender_address: Felt::from(0xCAFEu64),
        current_balance,
        bit_size: 32,

        auditor_key: None,
    };

    let result = withdraw(&account, params);
    assert!(result.is_err());
}

#[test]
fn test_withdraw_zero_amount() {
    use krusty_kms_crypto::StarkCurve;
    let account = create_test_account();
    let g = StarkCurve::generator();
    let current_balance = ElGamalCiphertext {
        l: StarkCurve::mul(&Felt::from(1000u128), Some(&g)),
        r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
    };

    let params = WithdrawParams {
        recipient_address: Felt::from(999u64),
        amount: 0,
        nonce: Felt::from(1u64),
        chain_id: Felt::from(1u64),
        tongo_address: Felt::from(123u64),
        sender_address: Felt::from(0xCAFEu64),

        current_balance,
        bit_size: 32,
        auditor_key: None,
    };

    let result = withdraw(&account, params);
    assert!(result.is_err());
}
