//! Account derivation discovery and cross-wallet compatibility tests.
//!
//! Verifies key derivation and address computation for Argent, Braavos,
//! and OpenZeppelin wallet schemes using a fixed test mnemonic.

use krusty_kms::{
    derive_private_key_with_coin_type, generate_candidates, stark_public_key, AccountClass,
    ArgentAccount, BraavosAccount, SaltPolicy, WalletType,
};
use starknet_types_core::felt::Felt;

// =============================================================================
// Shared test data
// =============================================================================

/// Test mnemonic used for all derivation tests.
///
/// Both Argent and Braavos wallets were created from this same mnemonic.
const MNEMONIC: &str =
    "person hunt couch artefact try half produce fatal large raw prison electric";

// -- Argent expected values ---------------------------------------------------

/// Stark private key derived via Argent's double derivation scheme.
///
/// Derivation: mnemonic → m/44'/60'/0'/0/0 (raw) → re-seed → m/44'/9004'/0'/0/0 → grindKey
const ARGENT_PRIVATE_KEY: &str =
    "0x0072e62ef0a3dc57f2891f0f27bc60b6951854990968d07660c6f245f14de67c";

/// Stark public key (x-coordinate) corresponding to `ARGENT_PRIVATE_KEY`.
const ARGENT_PUBLIC_KEY: &str =
    "0x048495fca9753cb0f4035eb4d2e2c1a22cc6d36fe4b73e17d9d6848333ff03a9";

/// On-chain account address. This is a **smart** account (server-provided salt).
///
/// Class hash: Argent v0.4.0 (`0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f`)
/// Contract version: 0.4.0 (get_version returns `{ major: 0, minor: 4, patch: 0 }`)
const ARGENT_ACCOUNT_ADDRESS: &str =
    "0x06bB92aC7bd2ba6922e497F8B9CCF4357559e3f3896396D5834D8A0B1ce1fC0E";

/// Argent v0.4.0 (Cairo 1) class hash — used for both standard and smart accounts.
const ARGENT_V040_CLASS_HASH: &str =
    "0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f";

// -- Braavos expected values --------------------------------------------------

/// The passphrase shown in the Braavos UI. **NOT used in BIP-39 seed generation.**
/// Braavos uses passphrase for wallet-level encryption only.
const BRAAVOS_PASSPHRASE: &str = "test-test-test";

/// Stark private key derived via Braavos's direct derivation.
///
/// Derivation: mnemonic → m/44'/9004'/0'/0/0 → grindKey (no passphrase in BIP-39)
const BRAAVOS_PRIVATE_KEY: &str =
    "0x04fc62347709307c23db0d065f4fd0a0f717e84d963dac1ac1eed740625700c3";

/// Stark public key (x-coordinate) corresponding to `BRAAVOS_PRIVATE_KEY`.
const BRAAVOS_PUBLIC_KEY: &str =
    "0x2985b4b4b2a370bdded9810e0c6cf74f82caf31dba039d2ece7eb8b8b80bb5a";

/// On-chain account address. Fully derivable from mnemonic.
const BRAAVOS_ACCOUNT_ADDRESS: &str =
    "0x05ddbfaa0b1daab3e0d8a78b5ba5cdfa00431ac62ca3d31fe3e8fabdbbf01626";

/// Braavos base deployment class hash.
///
/// Braavos uses a proxy-like architecture: accounts are always deployed with
/// this base class hash. On first transaction the contract auto-upgrades to
/// the full implementation via `replace_class_syscall`. This means the
/// *deployment address* (which is what we need for discovery) always depends
/// on this hash, not the full implementation hash.
///
/// Braavos base deployment class hash for counterfactual address computation.
const BRAAVOS_BASE_CLASS_HASH: &str =
    "0x03d16c7a9a60b0593bd202f660a28c5d76e0403601d9ccc7e4fa253b6a70c201";

// =============================================================================
//
//  ARGENT TESTS
//
// =============================================================================

// -- Key derivation -----------------------------------------------------------

/// Verify Argent's "double derivation" produces the expected private and public keys.
///
/// Derivation: mnemonic → ETH key at m/44'/60'/0'/0/0 (raw, no grind) →
/// re-seed as BIP-32 master → m/44'/9004'/0'/0/0 → grindKey.
#[test]
fn argent_double_derivation_key_matches() {
    let stark_key = krusty_kms::derive_argent_legacy_private_key(MNEMONIC, 0, 0).unwrap();
    let stark_pubkey = stark_public_key(&stark_key);

    assert_eq!(
        stark_key,
        Felt::from_hex(ARGENT_PRIVATE_KEY).unwrap(),
        "Private key must match the Argent double derivation: \
         mnemonic → raw ETH key (m/44'/60'/0'/0/0) → re-seed BIP-32 → m/44'/9004'/0'/0/0 → grindKey"
    );
    assert_eq!(
        stark_pubkey,
        Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap(),
        "Public key must match stark_public_key(private_key)"
    );
}

/// Confirm that Argent's derivation is NOT a simple direct `m/44'/9004'/0'/0/0`.
///
/// This test documents the incompatibility: a wallet using direct BIP-44
/// derivation (like Braavos) will derive a **different** key than old Argent
/// from the same mnemonic. Both wallets use coin type 9004 but the intermediate
/// ETH re-seeding step makes Argent's output completely different.
#[test]
fn argent_direct_derivation_does_not_match() {
    let pk_direct = derive_private_key_with_coin_type(MNEMONIC, 0, 0, 9004, None).unwrap();

    assert_ne!(
        pk_direct,
        Felt::from_hex(ARGENT_PRIVATE_KEY).unwrap(),
        "Direct m/44'/9004'/0'/0/0 produces a DIFFERENT key than old Argent. \
         This is the core vendor lock-in: Argent's double derivation via ETH \
         intermediate key makes its keys incompatible with direct BIP-44."
    );
}

// -- Address derivation -------------------------------------------------------

/// Verify that standard (non-smart) Argent v0.4.0 addresses ARE derivable
/// from the mnemonic alone.
///
/// Standard accounts use `salt = publicKey`, making the address deterministic.
/// The constructor calldata is `[0, publicKey, 0]`:
/// - `0` = `Signer::Starknet` enum variant index
/// - `publicKey` = the Stark public key (felt252)
/// - `0` = `Option::None` for the guardian (no guardian)
///
/// This calldata format comes from the Argent contract's Cairo constructor:
/// ```cairo
/// fn constructor(ref self: ContractState, owner: Signer, guardian: Option<Signer>)
/// ```
/// Where `Signer::Starknet(StarknetSigner { pubkey })` serializes as `[0, pubkey]`.
#[test]
fn argent_standard_account_address_is_derivable() {
    let pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();
    let class_hash = Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap();

    let argent = ArgentAccount::with_class_hash(class_hash);
    let standard_addr = argent
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    // The address is deterministic and non-zero
    assert_ne!(standard_addr, Felt::ZERO);
    let standard_addr_again = argent
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();
    assert_eq!(
        standard_addr, standard_addr_again,
        "Address must be deterministic"
    );

    // The test data account is a "smart" account with a server-provided salt,
    // so it won't match the standard salt=publicKey formula.
    let expected = Felt::from_hex(ARGENT_ACCOUNT_ADDRESS).unwrap();
    assert_ne!(
        standard_addr, expected,
        "Test account is a 'smart' account — its salt was provided by Argent's server, \
         not derived from the public key. Standard accounts DO match."
    );
}

/// End-to-end: mnemonic → Argent legacy keys → standard account address.
///
/// This is the full pipeline a wallet would use to discover standard Argent
/// accounts from a mnemonic, using krusty-kms APIs.
#[test]
fn argent_standard_discovery_end_to_end() {
    // Step 1: Derive keys using Argent's double derivation
    let pk = krusty_kms::derive_argent_legacy_private_key(MNEMONIC, 0, 0).unwrap();
    let pubk = stark_public_key(&pk);
    assert_eq!(pubk, Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap());

    // Step 2: Compute the standard account address
    let argent = ArgentAccount::with_class_hash(Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap());
    let addr = argent
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    // Step 3: This address can be checked on-chain for existence
    assert_ne!(
        addr,
        Felt::ZERO,
        "Derived a valid Argent address from mnemonic"
    );
}

/// Argent "smart" accounts receive their deployment salt from a server-side API,
/// not from the mnemonic or public key. These addresses cannot be derived locally.
#[test]
fn argent_smart_account_salt_is_not_derivable() {
    let pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();
    let expected = Felt::from_hex(ARGENT_ACCOUNT_ADDRESS).unwrap();
    let class_hash = Felt::from_hex(ARGENT_V040_CLASS_HASH).unwrap();

    // salt = publicKey (the standard formula) does NOT produce the right address
    let argent = ArgentAccount::with_class_hash(class_hash);
    let addr_with_pk_salt = argent
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();
    assert_ne!(
        addr_with_pk_salt, expected,
        "Smart account salt != publicKey — it was assigned by Argent's server"
    );

    // salt = 0 also doesn't match
    let addr_with_zero_salt = argent.calculate_address(&pubk, SaltPolicy::Zero).unwrap();
    assert_ne!(
        addr_with_zero_salt, expected,
        "Smart account salt != 0 either"
    );
}

// =============================================================================
//
//  BRAAVOS TESTS
//
// =============================================================================

// -- Key derivation -----------------------------------------------------------

/// Verify Braavos key derivation: direct BIP-44 with coin type 9004, no passphrase.
///
/// Braavos uses the simplest possible scheme — standard BIP-44 with the
/// Starknet coin type. No intermediate ETH key, no double derivation.
///
/// ```text
/// mnemonic
///   → PBKDF2 seed (passphrase = "")
///   → HMAC-SHA512("Bitcoin seed", seed) → master key
///   → BIP-32 derive m/44'/9004'/0'/0/0
///   → grindKey (SHA-256 rejection sampling mod Stark curve order)
///   → Stark private key
/// ```
#[test]
fn braavos_key_derivation_matches() {
    let pk = derive_private_key_with_coin_type(MNEMONIC, 0, 0, 9004, None).unwrap();
    let pubk = stark_public_key(&pk);

    assert_eq!(
        pk,
        Felt::from_hex(BRAAVOS_PRIVATE_KEY).unwrap(),
        "Braavos private key = derive(mnemonic, coin=9004, idx=0, acct=0, passphrase=None)"
    );
    assert_eq!(
        pubk,
        Felt::from_hex(BRAAVOS_PUBLIC_KEY).unwrap(),
        "Braavos public key = stark_public_key(private_key)"
    );
}

/// Verify the Braavos UI "passphrase" is NOT used in BIP-39 seed generation.
///
/// This is a critical finding. Braavos shows a passphrase field in its UI,
/// but this passphrase is used for **wallet-level encryption** only — it
/// protects the stored seed at rest. It is NOT passed to PBKDF2 during
/// BIP-39 seed generation.
///
/// If you pass the passphrase to BIP-39, you get a completely different key
/// that does NOT match the on-chain account.
#[test]
fn braavos_passphrase_is_not_used_in_derivation() {
    // Correct: no passphrase → matches on-chain account
    let pk_no_pass = derive_private_key_with_coin_type(MNEMONIC, 0, 0, 9004, None).unwrap();
    assert_eq!(
        pk_no_pass,
        Felt::from_hex(BRAAVOS_PRIVATE_KEY).unwrap(),
        "Empty passphrase produces the correct Braavos key"
    );

    // Wrong: passing the UI passphrase → completely different key
    let pk_with_pass =
        derive_private_key_with_coin_type(MNEMONIC, 0, 0, 9004, Some(BRAAVOS_PASSPHRASE)).unwrap();
    assert_ne!(
        pk_with_pass,
        Felt::from_hex(BRAAVOS_PRIVATE_KEY).unwrap(),
        "Passing the Braavos UI passphrase to BIP-39 produces the WRONG key"
    );
}

// -- Address derivation -------------------------------------------------------

/// Verify Braavos address derivation with the **base deployment** class hash.
///
/// Braavos uses a proxy-like architecture:
/// 1. Accounts are deployed with a lightweight "base" contract
/// 2. On first transaction, the base contract upgrades itself to the full
///    implementation via `replace_class_syscall`
/// 3. The deployment address depends on the BASE class hash, not the full one
///
/// Constructor calldata is simply `[publicKey]` — no signer type enum,
/// no guardian. Salt is the public key.
///
/// ```text
/// address = computeHashOnElements([
///     "STARKNET_CONTRACT_ADDRESS",
///     deployer = 0,
///     salt = publicKey,
///     classHash = 0x03d16c7a...c201,   // base deployment hash
///     hash([publicKey])                  // constructor calldata hash
/// ])
/// ```
#[test]
fn braavos_address_derivation_matches() {
    let pubk = Felt::from_hex(BRAAVOS_PUBLIC_KEY).unwrap();
    let braavos = BraavosAccount::with_class_hash(Felt::from_hex(BRAAVOS_BASE_CLASS_HASH).unwrap());
    let addr = braavos
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    assert_eq!(
        addr,
        Felt::from_hex(BRAAVOS_ACCOUNT_ADDRESS).unwrap(),
        "Braavos address must match: salt=pubkey, class=base_hash, calldata=[pubkey], deployer=0"
    );
}

/// Verify that `BraavosAccount::new()` uses the correct base deployment hash.
///
/// The default class hash was updated from the legacy hash (`0x00816dd...`)
/// to the base deployment hash (`0x03d16c7a...c201`) based on this discovery.
#[test]
fn braavos_default_class_hash_produces_correct_address() {
    let pubk = Felt::from_hex(BRAAVOS_PUBLIC_KEY).unwrap();
    let braavos = BraavosAccount::new();
    let addr = braavos
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    assert_eq!(
        addr,
        Felt::from_hex(BRAAVOS_ACCOUNT_ADDRESS).unwrap(),
        "BraavosAccount::new() must use the base deployment class hash"
    );
}

/// Verify that the old/legacy Braavos class hash does NOT produce the right address.
///
/// The legacy hash (`0x00816dd...`) was the full implementation hash, not the
/// base deployment hash. Using it for address computation gives the wrong result.
#[test]
fn braavos_legacy_class_hash_produces_wrong_address() {
    let pubk = Felt::from_hex(BRAAVOS_PUBLIC_KEY).unwrap();
    let braavos_legacy = BraavosAccount::with_class_hash(
        Felt::from_hex(krusty_kms::BraavosAccount::LEGACY_CLASS_HASH).unwrap(),
    );
    let addr = braavos_legacy
        .calculate_address(&pubk, SaltPolicy::PublicKey)
        .unwrap();

    assert_ne!(
        addr,
        Felt::from_hex(BRAAVOS_ACCOUNT_ADDRESS).unwrap(),
        "Legacy class hash (full implementation) does NOT produce the deployment address"
    );
}

// -- Multi-index discovery ----------------------------------------------------

/// Verify Braavos account discovery across multiple HD indices.
///
/// Wallets discover accounts by iterating `index = 0, 1, 2, ...`, deriving
/// the address at each index, and checking on-chain whether the contract is
/// deployed. This test verifies that each index produces a unique, non-zero
/// address and that index 0 matches the known test vector.
#[test]
fn braavos_multi_index_discovery() {
    let base_class = Felt::from_hex(BRAAVOS_BASE_CLASS_HASH).unwrap();
    let mut seen_addresses = Vec::new();

    for idx in 0..5u32 {
        let pk = derive_private_key_with_coin_type(MNEMONIC, idx, 0, 9004, None).unwrap();
        let pubk = stark_public_key(&pk);
        let braavos = BraavosAccount::with_class_hash(base_class);
        let addr = braavos
            .calculate_address(&pubk, SaltPolicy::PublicKey)
            .unwrap();

        assert_ne!(
            addr,
            Felt::ZERO,
            "Address at index {} must be non-zero",
            idx
        );
        assert!(
            !seen_addresses.contains(&addr),
            "Address at index {} must be unique",
            idx
        );
        seen_addresses.push(addr);

        if idx == 0 {
            assert_eq!(
                addr,
                Felt::from_hex(BRAAVOS_ACCOUNT_ADDRESS).unwrap(),
                "Index 0 must match the known test vector"
            );
        }
    }
}

// =============================================================================
//
//  DISCOVERY API TESTS — generate_candidates orchestration
//
// =============================================================================

/// Verify that `generate_candidates` produces at least one candidate for every
/// known wallet type when scanning a single derivation index.
///
/// Expected per-index breakdown:
/// - 1 Braavos (base deployment hash)
/// - 1 Argent  (new direct derivation, v0.4.0)
/// - 3 ArgentLegacy (legacy double derivation, v0.4.0 + v0.3.1 + v0.3.0)
/// - 4 ArgentCairo0 (proxy + 4 implementation hashes)
/// - 1 OpenZeppelin (latest manifest hash)
///
/// Total: 10 candidates per index.
#[test]
fn discovery_generates_candidates_for_all_wallet_types() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    let has_braavos = candidates
        .iter()
        .any(|c| c.wallet_type == WalletType::Braavos);
    let has_argent = candidates
        .iter()
        .any(|c| c.wallet_type == WalletType::Argent);
    let has_argent_legacy = candidates
        .iter()
        .any(|c| c.wallet_type == WalletType::ArgentLegacy);
    let has_argent_cairo0 = candidates
        .iter()
        .any(|c| c.wallet_type == WalletType::ArgentCairo0);
    let has_oz = candidates
        .iter()
        .any(|c| c.wallet_type == WalletType::OpenZeppelin);

    assert!(has_braavos, "Must have at least one Braavos candidate");
    assert!(has_argent, "Must have at least one Argent candidate");
    assert!(
        has_argent_legacy,
        "Must have at least one ArgentLegacy candidate"
    );
    assert!(
        has_argent_cairo0,
        "Must have at least one ArgentCairo0 candidate"
    );
    assert!(has_oz, "Must have at least one OpenZeppelin candidate");

    // 10 candidates per index: 1 braavos + 1 argent + 3 legacy + 4 cairo0 + 1 oz
    assert_eq!(
        candidates.len(),
        10,
        "Expected 10 candidates for 1 index, got {}",
        candidates.len()
    );
}

/// Verify that the Braavos candidate at index 0 matches the known test vector.
#[test]
fn discovery_braavos_candidate_matches_known_address() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    let braavos: Vec<_> = candidates
        .iter()
        .filter(|c| c.wallet_type == WalletType::Braavos && c.derivation_index == 0)
        .collect();

    assert_eq!(
        braavos.len(),
        1,
        "Expected exactly one Braavos candidate at index 0"
    );

    let candidate = &braavos[0];

    // Parse both as Felt for canonical comparison (avoids leading-zero mismatches)
    let candidate_addr = Felt::from_hex(&candidate.address).unwrap();
    let expected_addr = Felt::from_hex(BRAAVOS_ACCOUNT_ADDRESS).unwrap();
    assert_eq!(
        candidate_addr, expected_addr,
        "Braavos candidate address must match the known test vector"
    );

    let candidate_pubk = Felt::from_hex(&candidate.public_key).unwrap();
    let expected_pubk = Felt::from_hex(BRAAVOS_PUBLIC_KEY).unwrap();
    assert_eq!(
        candidate_pubk, expected_pubk,
        "Braavos candidate public key must match the known test vector"
    );
}

/// Verify that at least one ArgentLegacy candidate at index 0 has the correct
/// private/public key pair from the double derivation scheme.
#[test]
fn discovery_argent_legacy_candidate_has_correct_key() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    let legacy: Vec<_> = candidates
        .iter()
        .filter(|c| c.wallet_type == WalletType::ArgentLegacy && c.derivation_index == 0)
        .collect();

    assert!(
        !legacy.is_empty(),
        "Must have at least one ArgentLegacy candidate at index 0"
    );

    let expected_pk = Felt::from_hex(ARGENT_PRIVATE_KEY).unwrap();
    let expected_pubk = Felt::from_hex(ARGENT_PUBLIC_KEY).unwrap();

    let matching = legacy
        .iter()
        .filter(|c| {
            Felt::from_hex(&c.private_key).unwrap() == expected_pk
                && Felt::from_hex(&c.public_key).unwrap() == expected_pubk
        })
        .count();

    assert!(
        matching > 0,
        "At least one ArgentLegacy candidate must have the known private/public key pair"
    );
}

/// Verify that every candidate address is unique across all wallet types and indices.
#[test]
fn discovery_all_addresses_are_unique() {
    let candidates = generate_candidates(MNEMONIC, 2).unwrap();

    let mut seen = std::collections::HashSet::new();
    for candidate in &candidates {
        let addr = Felt::from_hex(&candidate.address).unwrap();
        assert!(
            seen.insert(addr),
            "Duplicate address found: {} (wallet_type={:?}, index={}, class_version={})",
            candidate.address,
            candidate.wallet_type,
            candidate.derivation_index,
            candidate.class_version
        );
    }

    assert_eq!(seen.len(), candidates.len(), "All addresses must be unique");
}

/// Verify that candidate count scales linearly with max_index.
#[test]
fn discovery_candidates_increase_with_max_index() {
    let count_1 = generate_candidates(MNEMONIC, 1).unwrap().len();
    let count_3 = generate_candidates(MNEMONIC, 3).unwrap().len();

    assert_eq!(
        count_3,
        count_1 * 3,
        "3 indices should produce exactly 3x the candidates of 1 index"
    );
}

/// Verify that an invalid mnemonic returns an error.
#[test]
fn discovery_invalid_mnemonic_returns_error() {
    let result = generate_candidates("not valid", 1);
    assert!(
        result.is_err(),
        "Invalid mnemonic must return Err, got {} candidates",
        result.unwrap().len()
    );
}

/// Verify that all candidate fields containing hex values start with "0x"
/// and parse as valid Felt values.
#[test]
fn discovery_each_candidate_has_valid_hex_fields() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    for candidate in &candidates {
        // All hex fields must start with "0x"
        assert!(
            candidate.address.starts_with("0x"),
            "Address must start with 0x: {}",
            candidate.address
        );
        assert!(
            candidate.public_key.starts_with("0x"),
            "Public key must start with 0x: {}",
            candidate.public_key
        );
        assert!(
            candidate.private_key.starts_with("0x"),
            "Private key must start with 0x: {}",
            candidate.private_key
        );
        assert!(
            candidate.class_hash.starts_with("0x"),
            "Class hash must start with 0x: {}",
            candidate.class_hash
        );

        // All hex fields must parse as valid Felt values
        assert!(
            Felt::from_hex(&candidate.address).is_ok(),
            "Address must be a valid Felt: {}",
            candidate.address
        );
        assert!(
            Felt::from_hex(&candidate.public_key).is_ok(),
            "Public key must be a valid Felt: {}",
            candidate.public_key
        );
        assert!(
            Felt::from_hex(&candidate.private_key).is_ok(),
            "Private key must be a valid Felt: {}",
            candidate.private_key
        );
        assert!(
            Felt::from_hex(&candidate.class_hash).is_ok(),
            "Class hash must be a valid Felt: {}",
            candidate.class_hash
        );
    }
}

/// Verify that different derivation indices produce different keys for the
/// same wallet type.
#[test]
fn discovery_different_indices_have_different_keys() {
    let candidates = generate_candidates(MNEMONIC, 2).unwrap();

    // Check each wallet type: index 0 and index 1 should have different public keys
    for wallet_type in [
        WalletType::Braavos,
        WalletType::Argent,
        WalletType::ArgentLegacy,
        WalletType::ArgentCairo0,
        WalletType::OpenZeppelin,
    ] {
        let idx0: Vec<_> = candidates
            .iter()
            .filter(|c| c.wallet_type == wallet_type && c.derivation_index == 0)
            .collect();
        let idx1: Vec<_> = candidates
            .iter()
            .filter(|c| c.wallet_type == wallet_type && c.derivation_index == 1)
            .collect();

        assert!(
            !idx0.is_empty() && !idx1.is_empty(),
            "Both indices must have candidates for {:?}",
            wallet_type
        );

        // Compare the first candidate's public key from each index
        let pubk_0 = Felt::from_hex(&idx0[0].public_key).unwrap();
        let pubk_1 = Felt::from_hex(&idx1[0].public_key).unwrap();
        assert_ne!(
            pubk_0, pubk_1,
            "{:?} index 0 and index 1 must have different public keys",
            wallet_type
        );
    }
}

/// Verify that each candidate has meaningful derivation metadata.
///
/// - `derivation_path` must be non-empty
/// - `class_version` must be non-empty
/// - Braavos should use the direct BIP-44 path format
/// - ArgentLegacy should describe the double derivation (ETH re-seed)
#[test]
fn discovery_candidate_contains_derivation_metadata() {
    let candidates = generate_candidates(MNEMONIC, 1).unwrap();

    for candidate in &candidates {
        assert!(
            !candidate.derivation_path.is_empty(),
            "derivation_path must not be empty for {:?}",
            candidate.wallet_type
        );
        assert!(
            !candidate.class_version.is_empty(),
            "class_version must not be empty for {:?}",
            candidate.wallet_type
        );
    }

    // Braavos uses direct BIP-44 path
    let braavos = candidates
        .iter()
        .find(|c| c.wallet_type == WalletType::Braavos)
        .unwrap();
    assert!(
        braavos.derivation_path.contains("m/44'/9004'/0'/0/0"),
        "Braavos derivation_path should contain the BIP-44 path, got: {}",
        braavos.derivation_path
    );

    // ArgentLegacy describes the double derivation
    let legacy = candidates
        .iter()
        .find(|c| c.wallet_type == WalletType::ArgentLegacy)
        .unwrap();
    assert!(
        legacy.derivation_path.contains("reseed") || legacy.derivation_path.contains("60'"),
        "ArgentLegacy derivation_path should describe the double derivation, got: {}",
        legacy.derivation_path
    );
}
