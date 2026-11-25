use super::super::{withdraw, WithdrawParams};
use super::support::{create_test_account, encrypt_balance_for_account};
use krusty_kms_common::ElGamalCiphertext;
use starknet_types_core::felt::Felt;

#[test]
fn test_withdraw_rejects_invalid_range_width_before_proving() {
    let mut account = create_test_account();
    account.set_balance(1000);
    let current_balance = encrypt_balance_for_account(&account, 1000, Felt::from(42u64));

    for bit_size in [0, 129] {
        let params = WithdrawParams {
            recipient_address: Felt::ONE,
            amount: 100,
            nonce: Felt::ONE,
            chain_id: Felt::ONE,
            tongo_address: Felt::ONE,
            sender_address: Felt::ONE,
            current_balance: current_balance.clone(),
            bit_size,
            auditor_key: None,
        };
        let error = withdraw(&account, params)
            .err()
            .expect("invalid width must fail");
        assert!(error.to_string().contains("bit_size"));
    }
}

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

/// The remaining audited balance must fit the pinned Tongo auditor's `u32`,
/// and the nonce its `u64`; reject before proving.
#[test]
fn test_withdraw_audit_hint_rejects_values_outside_tongo_widths() {
    use krusty_kms_common::KmsError;
    use krusty_kms_crypto::StarkCurve;
    let mut account = create_test_account();
    let params = |account: &crate::TongoAccount, nonce: Felt| WithdrawParams {
        recipient_address: Felt::ONE,
        amount: 100,
        nonce,
        chain_id: Felt::ONE,
        tongo_address: Felt::ONE,
        sender_address: Felt::ONE,
        current_balance: encrypt_balance_for_account(account, 0, Felt::from(42u64)),
        bit_size: 32,
        auditor_key: Some(StarkCurve::mul_generator(&Felt::from(888u64))),
    };

    account.set_balance(u128::from(u32::MAX) + 1000);
    let err = withdraw(&account, params(&account, Felt::ONE))
        .err()
        .expect("remaining audited balance above u32 must fail");
    assert!(
        matches!(err, KmsError::InvalidAmount(ref m) if m.contains("Tongo audit")),
        "{err:?}"
    );

    account.set_balance(1000);
    let wide_nonce = Felt::from(u128::from(u64::MAX) + 1);
    let err = withdraw(&account, params(&account, wide_nonce))
        .err()
        .expect("audit nonce above u64 must fail");
    assert!(
        matches!(err, KmsError::InvalidAmount(ref m) if m.contains("Tongo audit")),
        "{err:?}"
    );
}
