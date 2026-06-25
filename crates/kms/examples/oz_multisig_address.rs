use krusty_kms::{OpenZeppelinMultisig, SaltPolicy};
use starknet_types_core::felt::Felt;

fn main() -> Result<(), String> {
    // Replace this with the declared class hash of contracts/oz_multisig.
    let class_hash = Felt::from_hex("0x1234").map_err(|error| error.to_string())?;
    let signers = vec![
        Felt::from_hex("0x101").map_err(|error| error.to_string())?,
        Felt::from_hex("0x202").map_err(|error| error.to_string())?,
        Felt::from_hex("0x303").map_err(|error| error.to_string())?,
    ];

    let multisig = OpenZeppelinMultisig::from_class_hash(class_hash);
    let descriptor = multisig
        .deployment_descriptor(2, &signers, SaltPolicy::Explicit(Felt::from(42u64)))
        .map_err(|error| error.to_string())?;

    println!("class hash: {:#x}", descriptor.class_hash);
    println!("address: {}", descriptor.normalized_address_hex());
    println!("salt: {:#x}", descriptor.salt);
    println!("constructor calldata:");
    for felt in &descriptor.constructor_calldata {
        println!("  {felt:#x}");
    }

    Ok(())
}
