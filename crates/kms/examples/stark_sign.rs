use krusty_kms::{sign_stark_hash, stark_public_key};
use starknet_crypto::Felt;

fn main() -> Result<(), String> {
    let private_key =
        Felt::from_hex("0x78936b8dc426c649fccf3a9a8022b9795bdcd558dfb83956d66a25ae76992df")
            .map_err(|error| error.to_string())?;
    let message_hash = Felt::from_hex("0x1234").map_err(|error| error.to_string())?;

    let public_key = stark_public_key(&private_key);
    let signature =
        sign_stark_hash(&private_key, &message_hash).map_err(|error| error.to_string())?;

    println!("public key: {public_key:#x}");
    println!("signature.r: {:#x}", signature.r);
    println!("signature.s: {:#x}", signature.s);

    Ok(())
}
