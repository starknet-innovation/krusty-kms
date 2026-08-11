use super::super::{transfer, TransferParams};
use super::support::{create_test_account, encrypt_balance_for_account};
use krusty_kms_common::ElGamalCiphertext;
use starknet_types_core::felt::Felt;

#[test]
fn test_transfer() {
    use krusty_kms_crypto::StarkCurve;
    let mut account = create_test_account();
    account.set_balance(1000);
    let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
    let current_balance = encrypt_balance_for_account(&account, 1000, Felt::from(42u64));

    let params = TransferParams {
        recipient_public_key: recipient_key,
        amount: 100,
        nonce: Felt::from(1u64),
        chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
        tongo_address: Felt::from(123456u64),
        sender_address: Felt::from(0xCAFEu64),
        current_balance,
        bit_size: 16,

        auditor_pub_key: None,
    };

    let result = transfer(&account, params);
    assert!(result.is_ok(), "transfer failed: {:?}", result.err());
}

#[test]
fn test_transfer_rejects_mismatched_cipher_balance() {
    use krusty_kms_crypto::StarkCurve;
    let mut account = create_test_account();
    account.set_balance(1000);
    let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
    // Cipher encrypts 500 while account.balance() is 1000 — must fail the
    // cipher↔balance consistency check added for the audit fix.
    let current_balance = encrypt_balance_for_account(&account, 500, Felt::from(42u64));

    let params = TransferParams {
        recipient_public_key: recipient_key,
        amount: 100,
        nonce: Felt::from(1u64),
        chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
        tongo_address: Felt::from(123456u64),
        sender_address: Felt::from(0xCAFEu64),
        current_balance,
        bit_size: 16,
        auditor_pub_key: None,
    };

    let result = transfer(&account, params);
    match result {
        Ok(_) => panic!("mismatched cipher balance should be rejected"),
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains("storedBalance") || message.contains("encryption of balance"),
                "unexpected error: {message}"
            );
        }
    }
}

#[test]
fn test_transfer_insufficient_balance() {
    use krusty_kms_crypto::StarkCurve;
    let account = create_test_account();
    let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
    let g = StarkCurve::generator();
    let current_balance = ElGamalCiphertext {
        l: StarkCurve::mul(&Felt::from(1000u128), Some(&g)),
        r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
    };

    let params = TransferParams {
        recipient_public_key: recipient_key,
        amount: 2000,
        nonce: Felt::from(1u64),
        chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
        tongo_address: Felt::from(123456u64),
        sender_address: Felt::from(0xCAFEu64),
        current_balance,
        bit_size: 16,

        auditor_pub_key: None,
    };

    let result = transfer(&account, params);
    assert!(result.is_err());
}

#[test]
fn test_transfer_with_auditor() {
    use krusty_kms_crypto::StarkCurve;
    let mut account = create_test_account();
    account.set_balance(1000);
    let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
    let auditor_key = StarkCurve::mul_generator(&Felt::from(888u64));
    let current_balance = encrypt_balance_for_account(&account, 1000, Felt::from(42u64));

    let params = TransferParams {
        recipient_public_key: recipient_key,
        amount: 100,
        nonce: Felt::from(1u64),
        chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
        tongo_address: Felt::from(123456u64),
        sender_address: Felt::from(0xCAFEu64),
        current_balance,
        bit_size: 16,

        auditor_pub_key: Some(auditor_key),
    };

    let result = transfer(&account, params);
    assert!(result.is_ok(), "transfer failed: {:?}", result.err());
    let proof = result.unwrap();
    // Audit data should be present when auditor key is provided
    assert!(proof.audit_balance.is_some());
    assert!(proof.audit_transfer.is_some());
}

#[test]
fn test_transfer_zero_amount() {
    use krusty_kms_crypto::StarkCurve;
    let account = create_test_account();
    let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
    let g = StarkCurve::generator();
    let current_balance = ElGamalCiphertext {
        l: StarkCurve::mul(&Felt::from(1000u128), Some(&g)),
        r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
    };

    let params = TransferParams {
        recipient_public_key: recipient_key,
        amount: 0,
        nonce: Felt::from(1u64),
        chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
        tongo_address: Felt::from(123456u64),
        sender_address: Felt::from(0xCAFEu64),
        current_balance,
        bit_size: 16,

        auditor_pub_key: None,
    };

    let result = transfer(&account, params);
    assert!(result.is_err());
}
