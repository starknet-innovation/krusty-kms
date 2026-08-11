use super::super::{fund, FundParams};
use super::support::{create_test_account, encrypt_balance_for_account, TEST_MNEMONIC};
use crate::TongoAccount;
use krusty_kms_common::ElGamalCiphertext;
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
