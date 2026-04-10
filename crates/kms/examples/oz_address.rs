use krusty_kms::{
    derive_keypair_with_coin_type, OpenZeppelinAccount, SaltPolicy, STARKNET_COIN_TYPE,
};
use krusty_kms_common::ChainId;

fn main() -> Result<(), String> {
    let mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
    let keypair = derive_keypair_with_coin_type(mnemonic, 0, 0, STARKNET_COIN_TYPE, None)
        .map_err(|error| error.to_string())?;
    let public_key = keypair
        .public_key
        .to_affine()
        .map_err(|error| format!("{error:?}"))?
        .x();

    let oz = OpenZeppelinAccount::latest(ChainId::Sepolia).map_err(|error| error.to_string())?;
    let descriptor = oz
        .deployment_descriptor(&public_key, SaltPolicy::Zero)
        .map_err(|error| error.to_string())?;

    println!("public key x: {public_key:#x}");
    println!("class hash: {:#x}", descriptor.class_hash);
    println!("address: {}", descriptor.normalized_address_hex());
    println!("salt: {:#x}", descriptor.salt);

    Ok(())
}
