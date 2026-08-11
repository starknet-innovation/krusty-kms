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
