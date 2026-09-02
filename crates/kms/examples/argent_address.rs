//! Derive Argent account addresses from a mnemonic, for comparison against a
//! real wallet.
//!
//! The mnemonic comes from the `MNEMONIC` env var so it is never committed:
//!
//! ```sh
//! MNEMONIC="..." cargo run -p krusty-kms --example argent_address
//! MNEMONIC="..." INDEXES=3 cargo run -p krusty-kms --example argent_address
//! ```
//!
//! Argent has used two key schemes, and the same mnemonic yields a different
//! address under each, so both are printed:
//!
//! - **legacy** (old Argent X): `m/44'/60'/0'/0/0` raw, re-seeded as a new
//!   BIP-32 master, then `m/44'/9004'/0'/0/{i}` and `grindKey`.
//! - **direct**: `m/44'/9004'/0'/0/{i}` and `grindKey`.
//!
//! Private keys are deliberately not printed.

use krusty_kms::{
    derive_argent_legacy_private_key, derive_private_key_with_coin_type, stark_public_key,
    AccountClass, ArgentAccount, SaltPolicy, STARKNET_COIN_TYPE,
};
use starknet_types_core::felt::Felt;

fn main() -> Result<(), String> {
    let mnemonic = std::env::var("MNEMONIC")
        .map_err(|_| "set MNEMONIC=\"word word ...\" in the environment".to_string())?;
    let indexes: u32 = std::env::var("INDEXES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    // Standard Argent accounts salt with the public key, so the address is a
    // pure function of the mnemonic and the class hash. Argent smart accounts
    // are assigned their salt server-side and will not appear here.
    for index in 0..indexes {
        for (scheme, private_key) in [
            (
                "legacy",
                derive_argent_legacy_private_key(&mnemonic, index, 0),
            ),
            (
                "direct",
                derive_private_key_with_coin_type(&mnemonic, index, 0, STARKNET_COIN_TYPE, None),
            ),
        ] {
            let public_key = stark_public_key(&private_key.map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;

            println!("index {index} [{scheme}]  pubkey {public_key:#x}");
            for (version, class_hash) in [
                ("v0.4.0", ArgentAccount::CLASS_HASH),
                ("v0.3.1", ArgentAccount::CLASS_HASH_V031),
                ("v0.3.0", ArgentAccount::CLASS_HASH_V030),
            ] {
                let account = ArgentAccount::try_with_class_hash(
                    Felt::from_hex(class_hash).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                let address = account
                    .calculate_address(&public_key, SaltPolicy::PublicKey)
                    .map_err(|e| e.to_string())?;
                println!("    {version}  0x{address:064x}");
            }
        }
    }

    Ok(())
}
