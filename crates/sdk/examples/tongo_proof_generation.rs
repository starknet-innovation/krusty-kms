use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_crypto::StarkCurve;
use krusty_kms_sdk::{fund, FundParams, TongoAccount};
use starknet_types_core::felt::Felt;

fn main() -> Result<(), String> {
    let contract_address = Felt::from_hex("0x123456789").map_err(|error| error.to_string())?;
    let account = TongoAccount::from_private_key(Felt::from(12345u64), contract_address)
        .map_err(|error| error.to_string())?;

    let generator = StarkCurve::generator();
    let current_balance = ElGamalCiphertext {
        l: generator.clone(),
        r: generator,
    };

    let proof = fund(
        &account,
        FundParams {
            amount: 100,
            nonce: Felt::from(1u64),
            chain_id: Felt::from_hex("0x534e5f5345504f4c4941")
                .map_err(|error| error.to_string())?,
            tongo_address: contract_address,
            sender_address: Felt::ZERO,
            auditor_pub_key: None,
            current_balance,
        },
    )
    .map_err(|error| error.to_string())?;

    println!("funded amount: {}", proof.amount);
    println!(
        "account public key x: {:#x}",
        proof
            .y
            .to_affine()
            .map_err(|error| format!("{error:?}"))?
            .x()
    );

    Ok(())
}
