use super::super::{ragequit, RagequitParams};
use super::support::{create_test_account, encrypt_balance_for_account};
use starknet_types_core::felt::Felt;

#[test]
fn test_ragequit() {
    let mut account = create_test_account();
    account.set_balance(1000);

    let random = Felt::from(42u64);
    let current_balance = encrypt_balance_for_account(&account, 1000, random);

    let params = RagequitParams {
        recipient_address: Felt::from(999u64),
        nonce: Felt::from(1u64),
        chain_id: Felt::from(1u64),
        tongo_address: Felt::from(123u64),
        sender_address: Felt::from(0xCAFEu64),
        current_balance,

        auditor_key: None,
    };

    let result = ragequit(&account, params);
    assert!(result.is_ok(), "ragequit failed: {:?}", result.err());
    let proof = result.unwrap();
    assert_eq!(proof.amount, 1000);
}

/// The pinned Tongo auditor reads a `u64` nonce; reject a wider one before
/// proving.
#[test]
fn test_ragequit_audit_hint_rejects_nonce_above_u64() {
    use krusty_kms_common::KmsError;
    use krusty_kms_crypto::StarkCurve;
    let mut account = create_test_account();
    account.set_balance(1000);
    let params = RagequitParams {
        recipient_address: Felt::from(999u64),
        nonce: Felt::from(u128::from(u64::MAX) + 1),
        chain_id: Felt::ONE,
        tongo_address: Felt::ONE,
        sender_address: Felt::ONE,
        current_balance: encrypt_balance_for_account(&account, 1000, Felt::from(42u64)),
        auditor_key: Some(StarkCurve::mul_generator(&Felt::from(888u64))),
    };
    let err = ragequit(&account, params)
        .err()
        .expect("audit nonce above u64 must fail");
    assert!(
        matches!(err, KmsError::InvalidAmount(ref m) if m.contains("Tongo audit")),
        "{err:?}"
    );
}
