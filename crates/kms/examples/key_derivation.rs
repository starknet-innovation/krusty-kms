use krusty_kms::{
    derive_keypair_with_coin_type, derive_nostr_keypair, NOSTR_COIN_TYPE, STARKNET_COIN_TYPE,
    TONGO_COIN_TYPE,
};

fn main() -> Result<(), String> {
    let mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";

    let starknet = derive_keypair_with_coin_type(mnemonic, 0, 0, STARKNET_COIN_TYPE, None)
        .map_err(|error| error.to_string())?;
    let starknet_public = starknet
        .public_key
        .to_affine()
        .map_err(|error| format!("{error:?}"))?
        .x();

    let tongo = derive_keypair_with_coin_type(mnemonic, 0, 0, TONGO_COIN_TYPE, None)
        .map_err(|error| error.to_string())?;
    let tongo_public = tongo
        .public_key
        .to_affine()
        .map_err(|error| format!("{error:?}"))?
        .x();

    let nostr = derive_nostr_keypair(mnemonic, 0, 0, None).map_err(|error| error.to_string())?;

    // Keep secret export as an explicit boundary in real applications.
    println!("starknet public x: {starknet_public:#x}");
    println!("tongo public x: {tongo_public:#x}");
    println!("nostr coin type: {NOSTR_COIN_TYPE}");
    println!("nostr public x-only: {}", hex::encode(nostr.public_key));

    Ok(())
}
