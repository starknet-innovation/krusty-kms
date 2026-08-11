use crate::TongoAccount;
use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_crypto::StarkCurve;
use starknet_types_core::felt::Felt;

pub(super) const TEST_MNEMONIC: &str =
    "habit hope tip crystal because grunt nation idea electric witness alert like";

pub(super) fn create_test_account() -> TongoAccount {
    let contract_address = Felt::from(123456u64);
    let mut account =
        TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
    account.set_balance(1000);
    account
}

pub(super) fn encrypt_balance_for_account(
    account: &TongoAccount,
    balance: u128,
    random: Felt,
) -> ElGamalCiphertext {
    let g = StarkCurve::generator();
    let pk_r = StarkCurve::mul(&random, Some(account.owner_public_key()));
    let r = StarkCurve::mul(&random, Some(&g));

    if balance == 0 {
        return ElGamalCiphertext { l: pk_r, r };
    }

    let g_b = StarkCurve::mul(&Felt::from(balance), Some(&g));
    ElGamalCiphertext {
        l: StarkCurve::add(&g_b, &pk_r),
        r,
    }
}
