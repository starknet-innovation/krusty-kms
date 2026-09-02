//! Candidate and keypair generation from a mnemonic. Performs no network I/O.

use super::types::{CandidateAccount, DerivationType, DerivedKeypair, WalletType};
use crate::account::calculate_contract_address;
use crate::account_class::{AccountClass, ArgentAccount, BraavosAccount, SaltPolicy};
use crate::derivation::{derive_argent_legacy_private_key, derive_private_key_with_coin_type};
use crate::mnemonic::validate_mnemonic;
use crate::stark_signing::stark_public_key;
use krusty_kms_common::Result;
use starknet_types_core::felt::Felt;

// ---------------------------------------------------------------------------
// Known class hashes
// ---------------------------------------------------------------------------

/// Braavos base deployment hash (address depends on this, NOT the full implementation).
const BRAAVOS_BASE: &str = "0x03d16c7a9a60b0593bd202f660a28c5d76e0403601d9ccc7e4fa253b6a70c201";

/// Argent Cairo 1 v0.4.0 class hash.
const ARGENT_V040: &str = ArgentAccount::CLASS_HASH;

/// Argent Cairo 0 proxy class hash.
const ARGENT_PROXY: &str = "0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918";

/// Argent Cairo 0 implementation v0.2.4.
const ARGENT_IMPL_V024: &str = "0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2";

/// Argent Cairo 0 implementation v0.2.3.
const ARGENT_IMPL_V023: &str = "0x01a7820094feaf82d53f53f214b81292d717e7bb9a92bb2488092cd306f3993f";

/// Argent Cairo 0 implementation v0.2.2.
const ARGENT_IMPL_V022: &str = "0x03e327de1c40540b98d05cbcb13552008e36f0ec8d61d46956d2f9752c294328";

/// Argent Cairo 0 implementation v0.2.1.
const ARGENT_IMPL_V021: &str = "0x07e28fb0161d10d1cf7fe1f13e7ca57bce062731a3bd04494dfd2d0412699727";

/// OpenZeppelin v3.0.0 class hash.
const OZ_V300: &str = "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381";

/// Pre-computed `selector("initialize")` — the sn_keccak of `"initialize"`.
const INITIALIZE_SELECTOR: &str =
    "0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463";

/// Starknet coin type for BIP-44 derivation (SNIP-44).
const STARKNET_COIN_TYPE: u32 = 9004;

/// Format a Felt as a `0x`-prefixed lowercase hex string.
fn felt_hex(f: &Felt) -> String {
    format!("{:#x}", f)
}

/// Derive all unique keypairs for a mnemonic without computing addresses.
///
/// Returns one keypair per derivation scheme per index:
/// - **Direct**: `m/44'/9004'/0'/0/{index}` — the key used by Braavos, new Argent, and OZ
/// - **ArgentLegacy**: double derivation via ETH key — the key used by old Argent
///
/// These public keys can be used to query external APIs (e.g., Argent's smart
/// account discovery endpoint) to find Argent smart accounts, whose deployment
/// salt is assigned server-side and so cannot be reconstructed locally.
/// Standard Argent accounts salt with the public key and *are* derived here; an
/// earlier mismatch against a real on-chain account was misattributed to this
/// salt, when the cause was the constructor calldata (see
/// `docs/design/2026-09-02-argent-constructor-layout.md`).
///
/// This is much cheaper than `generate_candidates` since it skips address computation.
pub fn derive_discovery_keypairs(mnemonic: &str, max_index: u32) -> Result<Vec<DerivedKeypair>> {
    validate_mnemonic(mnemonic)?;

    let mut keypairs = Vec::with_capacity((max_index * 2) as usize);

    for index in 0..max_index {
        // Direct derivation (Braavos / new Argent / OZ all share this key)
        let direct_pk =
            derive_private_key_with_coin_type(mnemonic, index, 0, STARKNET_COIN_TYPE, None)?;
        let direct_pubk = stark_public_key(&direct_pk)?;
        keypairs.push(DerivedKeypair {
            derivation_type: DerivationType::Direct,
            public_key: felt_hex(&direct_pubk),
            private_key: felt_hex(&direct_pk),
            derivation_index: index,
            derivation_path: format!("m/44'/9004'/0'/0/{index}"),
        });

        // Argent legacy double derivation
        let legacy_pk = derive_argent_legacy_private_key(mnemonic, index, 0)?;
        let legacy_pubk = stark_public_key(&legacy_pk)?;
        keypairs.push(DerivedKeypair {
            derivation_type: DerivationType::ArgentLegacy,
            public_key: felt_hex(&legacy_pubk),
            private_key: felt_hex(&legacy_pk),
            derivation_index: index,
            derivation_path: format!("m/44'/60'/0'/0/0 -> m/44'/9004'/0'/0/{index}"),
        });
    }

    Ok(keypairs)
}

/// Generate all candidate account addresses for a mnemonic.
///
/// Iterates through derivation indices `0..max_index` and generates candidate
/// addresses for every known wallet type and class hash combination:
///
/// - **Braavos**: direct derivation, base deployment class hash
/// - **Argent**: direct derivation, Cairo 1 v0.4.0
/// - **Argent legacy**: double derivation (via ETH key), Cairo 1 v0.4.0/v0.3.1/v0.3.0
/// - **Argent Cairo 0**: double derivation, proxy + implementation pattern
/// - **OpenZeppelin**: direct derivation, OZ v3.0.0 with both salt policies
///   (salt = public key matching this project's deploy flow, and salt = 0)
///
/// Does NOT hit the network. Returns all mathematically possible addresses.
/// Use with an RPC provider to filter to actually deployed accounts.
pub fn generate_candidates(mnemonic: &str, max_index: u32) -> Result<Vec<CandidateAccount>> {
    validate_mnemonic(mnemonic)?;

    let mut candidates = Vec::new();

    // Parse class hashes once.
    let braavos_hash = Felt::from_hex(BRAAVOS_BASE).unwrap();
    let argent_v040_hash = Felt::from_hex(ARGENT_V040).unwrap();
    let proxy_hash = Felt::from_hex(ARGENT_PROXY).unwrap();
    let impl_v024 = Felt::from_hex(ARGENT_IMPL_V024).unwrap();
    let impl_v023 = Felt::from_hex(ARGENT_IMPL_V023).unwrap();
    let impl_v022 = Felt::from_hex(ARGENT_IMPL_V022).unwrap();
    let impl_v021 = Felt::from_hex(ARGENT_IMPL_V021).unwrap();
    let oz_hash = Felt::from_hex(OZ_V300).unwrap();
    let initialize_selector = Felt::from_hex(INITIALIZE_SELECTOR).unwrap();

    // Class hash, label and layout come from the canonical Argent table.
    let legacy_cairo1_classes = ArgentAccount::known_classes();

    // Cairo 0 proxy implementation hashes with labels.
    let cairo0_impls: &[(Felt, &str)] = &[
        (impl_v024, "proxy+v0.2.4"),
        (impl_v023, "proxy+v0.2.3"),
        (impl_v022, "proxy+v0.2.2"),
        (impl_v021, "proxy+v0.2.1"),
    ];

    for index in 0..max_index {
        // ---------------------------------------------------------------
        // (a) Direct derivation — shared by Braavos, new Argent, OZ
        // ---------------------------------------------------------------
        let direct_pk =
            derive_private_key_with_coin_type(mnemonic, index, 0, STARKNET_COIN_TYPE, None)?;
        let direct_pubk = stark_public_key(&direct_pk)?;
        let direct_path = format!("m/44'/9004'/0'/0/{index}");

        // Braavos
        let braavos_addr =
            BraavosAccount::new().calculate_address(&direct_pubk, SaltPolicy::PublicKey)?;
        candidates.push(CandidateAccount {
            wallet_type: WalletType::Braavos,
            class_hash: felt_hex(&braavos_hash),
            address: felt_hex(&braavos_addr),
            public_key: felt_hex(&direct_pubk),
            private_key: felt_hex(&direct_pk),
            derivation_index: index,
            derivation_path: direct_path.clone(),
            class_version: "base".to_string(),
        });

        // Argent — v0.4.0
        // ArgentAccount::new() *is* the v0.4.0 preset; don't restate its layout.
        let argent_addr =
            ArgentAccount::new().calculate_address(&direct_pubk, SaltPolicy::PublicKey)?;
        candidates.push(CandidateAccount {
            wallet_type: WalletType::Argent,
            class_hash: felt_hex(&argent_v040_hash),
            address: felt_hex(&argent_addr),
            public_key: felt_hex(&direct_pubk),
            private_key: felt_hex(&direct_pk),
            derivation_index: index,
            derivation_path: direct_path.clone(),
            class_version: "v0.4.0".to_string(),
        });

        // OpenZeppelin — v3.0.0, both salt policies. The deploy/gateway flows
        // default to salt = public key (SaltPolicy::PublicKey), so recovery
        // must cover that variant or it misses accounts this project deployed
        // itself; salt = 0 is kept for externally-deployed OZ accounts.
        let oz_addr_salt_pubk =
            calculate_contract_address(&direct_pubk, &oz_hash, &[direct_pubk], &Felt::ZERO)?;
        candidates.push(CandidateAccount {
            wallet_type: WalletType::OpenZeppelin,
            class_hash: felt_hex(&oz_hash),
            address: felt_hex(&oz_addr_salt_pubk),
            public_key: felt_hex(&direct_pubk),
            private_key: felt_hex(&direct_pk),
            derivation_index: index,
            derivation_path: direct_path.clone(),
            class_version: "v3.0.0 salt-pubkey".to_string(),
        });

        let oz_addr_salt_zero =
            calculate_contract_address(&Felt::ZERO, &oz_hash, &[direct_pubk], &Felt::ZERO)?;
        candidates.push(CandidateAccount {
            wallet_type: WalletType::OpenZeppelin,
            class_hash: felt_hex(&oz_hash),
            address: felt_hex(&oz_addr_salt_zero),
            public_key: felt_hex(&direct_pubk),
            private_key: felt_hex(&direct_pk),
            derivation_index: index,
            derivation_path: direct_path,
            class_version: "v3.0.0".to_string(),
        });

        // ---------------------------------------------------------------
        // (b) Legacy double derivation — old Argent
        // ---------------------------------------------------------------
        let legacy_pk = derive_argent_legacy_private_key(mnemonic, index, 0)?;
        let legacy_pubk = stark_public_key(&legacy_pk)?;
        let legacy_path = format!("m/44'/60'/0'/0/0 -> m/44'/9004'/0'/0/{index}");

        // Cairo 1 class hashes via legacy derivation
        for (hash, version, layout) in &legacy_cairo1_classes {
            let addr = ArgentAccount::with_class_hash_and_layout(*hash, *layout)
                .calculate_address(&legacy_pubk, SaltPolicy::PublicKey)?;
            candidates.push(CandidateAccount {
                wallet_type: WalletType::ArgentLegacy,
                class_hash: felt_hex(hash),
                address: felt_hex(&addr),
                public_key: felt_hex(&legacy_pubk),
                private_key: felt_hex(&legacy_pk),
                derivation_index: index,
                derivation_path: legacy_path.clone(),
                class_version: version.to_string(),
            });
        }

        // Cairo 0 proxy candidates
        for (impl_hash, version) in cairo0_impls {
            let calldata = vec![
                *impl_hash,
                initialize_selector,
                Felt::from(2u64),
                legacy_pubk,
                Felt::ZERO,
            ];
            let addr =
                calculate_contract_address(&legacy_pubk, &proxy_hash, &calldata, &Felt::ZERO)?;
            candidates.push(CandidateAccount {
                wallet_type: WalletType::ArgentCairo0,
                class_hash: felt_hex(&proxy_hash),
                address: felt_hex(&addr),
                public_key: felt_hex(&legacy_pubk),
                private_key: felt_hex(&legacy_pk),
                derivation_index: index,
                derivation_path: legacy_path.clone(),
                class_version: version.to_string(),
            });
        }
    }

    Ok(candidates)
}
