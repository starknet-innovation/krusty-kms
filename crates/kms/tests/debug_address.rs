use krusty_kms::{derive_keypair_with_coin_type, derive_oz_account_address, STARKNET_COIN_TYPE};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};

#[test]
fn debug_account_address_calculation() {
    // Test vector from Swift
    let mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
    let expected_private = "0x78936b8dc426c649fccf3a9a8022b9795bdcd558dfb83956d66a25ae76992df";
    let expected_public = "0x426212993d56613e1886a4cbc5b58810570023581c2aab0b423277776b79d2e";
    let expected_address = "0x6df2d05138d501f6aafe03c1d95b9ff824e2d96821934cd3d8148801865fefe";

    // Derive keys
    let keypair = derive_keypair_with_coin_type(mnemonic, 0, 0, STARKNET_COIN_TYPE, None)
        .expect("Should derive key");

    let public_key_x = keypair
        .public_key
        .to_affine()
        .expect("Should convert to affine")
        .x();

    println!("\n=== Account Address Calculation Debug ===\n");
    println!("Step 1: Keys");
    println!("  Private (expected): {}", expected_private);
    println!("  Private (derived):  {:#x}", keypair.private_key);
    println!("  Public (expected):  {}", expected_public);
    println!("  Public (derived):   {:#x}", public_key_x);
    println!();

    // Manually calculate each step
    let oz_class_hash =
        Felt::from_hex("0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564")
            .expect("Should parse class hash");
    let salt = Felt::ZERO;
    let deployer = Felt::ZERO;

    println!("Step 2: Inputs");
    println!("  Public Key:  {:#x}", public_key_x);
    println!("  Class Hash:  {:#x}", oz_class_hash);
    println!("  Salt:        {:#x}", salt);
    println!("  Deployer:    {:#x}", deployer);
    println!();

    // Step 3: Hash calldata
    println!("Step 3: Calldata Hashing");
    let calldata = vec![public_key_x];
    println!("  Calldata array: [{:#x}]", calldata[0]);
    println!("  Calldata length: {}", calldata.len());

    // Chain hash
    let mut chain_hash = Felt::ZERO;
    for (i, element) in calldata.iter().enumerate() {
        let prev = chain_hash;
        chain_hash = Pedersen::hash(&chain_hash, element);
        println!(
            "  Step 3.{}: pedersen({:#x}, {:#x}) = {:#x}",
            i + 1,
            prev,
            element,
            chain_hash
        );
    }

    // Hash with length
    let length = Felt::from(calldata.len() as u64);
    let calldata_hash = Pedersen::hash(&chain_hash, &length);
    println!(
        "  Step 3.final: pedersen({:#x}, {:#x}) = {:#x}",
        chain_hash, length, calldata_hash
    );
    println!();

    // Step 4: Prefix - short string encoding
    println!("Step 4: Prefix Encoding");
    let prefix = "STARKNET_CONTRACT_ADDRESS";
    println!("  Prefix string: '{}'", prefix);

    // Short string encoding (ASCII bytes as big-endian integer)
    let prefix_felt = Felt::from_bytes_be_slice(prefix.as_bytes());
    println!("  Short string encoding: {:#x}", prefix_felt);
    println!("  Expected:              0x535441524b4e45545f434f4e54524143545f41444452455353");
    println!();

    // Step 5: Address calculation
    println!("Step 5: Address Hash Chain");
    let mut current = prefix_felt;
    println!("  Start:                {:#x}", current);

    current = Pedersen::hash(&current, &deployer);
    println!("  After deployer:       {:#x}", current);

    current = Pedersen::hash(&current, &salt);
    println!("  After salt:           {:#x}", current);

    current = Pedersen::hash(&current, &oz_class_hash);
    println!("  After class_hash:     {:#x}", current);

    current = Pedersen::hash(&current, &calldata_hash);
    println!("  After calldata_hash:  {:#x}", current);
    println!();

    // Final result
    println!("Step 6: Result");
    println!("  Expected: {}", expected_address);
    println!("  Derived:  {:#x}", current);
    println!(
        "  Match:    {}",
        format!("{:#x}", current) == expected_address
    );
    println!();

    // Use the actual function
    let derived_address = derive_oz_account_address(&public_key_x, &oz_class_hash, Some(&salt))
        .expect("Should derive address");
    println!("Step 7: Using derive_oz_account_address function");
    println!("  Result:   {:#x}", derived_address);
    println!("  Expected: {}", expected_address);
    println!(
        "  Match:    {}",
        format!("{:#x}", derived_address) == expected_address
    );
}
