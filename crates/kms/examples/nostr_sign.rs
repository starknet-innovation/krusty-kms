use krusty_kms::{nostr_public_key, sign_nostr_event_id};

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| format!("expected exactly {N} bytes"))
}

fn main() -> Result<(), String> {
    let private_key =
        decode_array::<32>("1dce8d2ec6184cca9433f8f7b2702d9014936627ce0f50926f471e52946d0f4c")?;
    let event_id =
        decode_array::<32>("6c3fd336b5457a0f2b74959f177a5c5e7f9ab75cdb4ab7a3ec7aaf1e2a3d2b13")?;

    let public_key = nostr_public_key(&private_key).map_err(|error| error.to_string())?;
    let signature =
        sign_nostr_event_id(&private_key, &event_id).map_err(|error| error.to_string())?;

    println!("public key: {}", hex::encode(public_key));
    println!("signature: {}", hex::encode(signature.signature));

    Ok(())
}
