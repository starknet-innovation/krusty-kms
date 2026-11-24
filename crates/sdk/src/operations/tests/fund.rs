use super::super::{fund, FundParams};
use super::support::{create_test_account, encrypt_balance_for_account, TEST_MNEMONIC};
use crate::TongoAccount;
use krusty_kms_common::{ElGamalCiphertext, KmsError};
use krusty_kms_crypto::StarkCurve;
use starknet_types_core::felt::Felt;

#[test]
fn test_fund() {
    let account = create_test_account();
    let contract_address = Felt::from(123456u64);

    // Create dummy current balance (zero balance for first fund)
    let current_balance = ElGamalCiphertext {
        l: StarkCurve::generator(),
        r: StarkCurve::generator(),
    };

    let params = FundParams {
        amount: 100,
        nonce: Felt::from(1u64),
        chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(), // SN_SEPOLIA
        tongo_address: contract_address,
        sender_address: Felt::from(0xCAFEu64),

        auditor_pub_key: None,
        current_balance,
    };

    let result = fund(&account, params);
    assert!(result.is_ok());
    let proof = result.unwrap();
    assert_eq!(proof.amount, 100);
    assert!(proof.audit.is_none());
}

#[test]
fn test_fund_zero_amount() {
    let account = create_test_account();
    let contract_address = Felt::from(123456u64);

    let current_balance = ElGamalCiphertext {
        l: StarkCurve::generator(),
        r: StarkCurve::generator(),
    };

    let params = FundParams {
        amount: 0,
        nonce: Felt::from(1u64),
        chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
        tongo_address: contract_address,
        sender_address: Felt::from(0xCAFEu64),

        auditor_pub_key: None,
        current_balance,
    };

    let result = fund(&account, params);
    assert!(result.is_err());
}

#[test]
fn test_fund_with_auditor() {
    // Create account with zero balance (matching the cipher we'll create)
    let contract_address = Felt::from(123456u64);
    let mut account =
        TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
    account.set_balance(0); // Must match the cipher's encrypted value

    let random = Felt::from(12345u64);
    let current_balance = encrypt_balance_for_account(&account, 0, random);

    // Create an auditor public key
    let auditor_pub_key = StarkCurve::mul_generator(&Felt::from(9999u64));

    let params = FundParams {
        amount: 100,
        nonce: Felt::from(1u64),
        chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
        tongo_address: contract_address,
        sender_address: Felt::from(0xCAFEu64),

        auditor_pub_key: Some(auditor_pub_key),
        current_balance,
    };

    let result = fund(&account, params);
    assert!(result.is_ok(), "fund failed: {:?}", result.err());
    let proof = result.unwrap();
    assert_eq!(proof.amount, 100);
    // With auditor, audit should be present
    assert!(proof.audit.is_some());
}

/// A balance near `u128::MAX` plus the fund amount must be rejected instead of
/// wrapping into a small audited balance (L-1).
#[test]
fn test_fund_rejects_funded_balance_overflow() {
    let contract_address = Felt::from(123456u64);
    let mut account =
        TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
    account.set_balance(u128::MAX - 50);
    let current_balance = encrypt_balance_for_account(&account, 0, Felt::from(12345u64));

    let params = FundParams {
        amount: 100,
        nonce: Felt::from(1u64),
        chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
        tongo_address: contract_address,
        sender_address: Felt::from(0xCAFEu64),
        // The audited balance is the only path that adds to the balance.
        auditor_pub_key: Some(StarkCurve::mul_generator(&Felt::from(9999u64))),
        current_balance,
    };

    let err = fund(&account, params)
        .err()
        .expect("fund must reject a wrapping balance");
    assert!(matches!(err, KmsError::InvalidAmount(_)), "{err:?}");
}

fn fund_params_with_auditor(account: &TongoAccount, nonce: Felt, auditor: bool) -> FundParams {
    FundParams {
        amount: 1,
        nonce,
        chain_id: Felt::ONE,
        tongo_address: Felt::from(123456u64),
        sender_address: Felt::from(0xCAFEu64),
        auditor_pub_key: auditor.then(|| StarkCurve::mul_generator(&Felt::from(9999u64))),
        current_balance: encrypt_balance_for_account(account, 0, Felt::from(12345u64)),
    }
}

/// The pinned Tongo auditor reads a `u32` balance and a `u64` nonce; an
/// auditor-enabled fund must fail before proving instead of emitting an
/// unreadable hint, while the same inputs still work without an auditor.
#[test]
fn test_fund_audit_hint_rejects_values_outside_tongo_widths() {
    let mut account = create_test_account();
    account.set_balance(u128::from(u32::MAX));
    let err = fund(
        &account,
        fund_params_with_auditor(&account, Felt::ONE, true),
    )
    .err()
    .expect("audited balance above u32 must fail");
    assert!(
        matches!(err, KmsError::InvalidAmount(ref m) if m.contains("Tongo audit")),
        "{err:?}"
    );
    assert!(fund(
        &account,
        fund_params_with_auditor(&account, Felt::ONE, false)
    )
    .is_ok());

    account.set_balance(0);
    let wide_nonce = Felt::from(u128::from(u64::MAX) + 1);
    let err = fund(
        &account,
        fund_params_with_auditor(&account, wide_nonce, true),
    )
    .err()
    .expect("audit nonce above u64 must fail");
    assert!(
        matches!(err, KmsError::InvalidAmount(ref m) if m.contains("Tongo audit")),
        "{err:?}"
    );
    assert!(fund(
        &account,
        fund_params_with_auditor(&account, wide_nonce, false)
    )
    .is_ok());
}
