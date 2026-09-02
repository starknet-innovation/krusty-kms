//! Shared test data: fixed mnemonic and expected derivation vectors.

/// Test mnemonic used for all derivation tests.
///
/// Both Argent and Braavos wallets were created from this same mnemonic.
pub const MNEMONIC: &str =
    "person hunt couch artefact try half produce fatal large raw prison electric";

// -- Argent expected values ---------------------------------------------------

/// Stark private key derived via Argent's double derivation scheme.
///
/// Derivation: mnemonic → m/44'/60'/0'/0/0 (raw) → re-seed → m/44'/9004'/0'/0/0 → grindKey
pub const ARGENT_PRIVATE_KEY: &str =
    "0x0072e62ef0a3dc57f2891f0f27bc60b6951854990968d07660c6f245f14de67c";

/// Stark public key (x-coordinate) corresponding to `ARGENT_PRIVATE_KEY`.
pub const ARGENT_PUBLIC_KEY: &str =
    "0x048495fca9753cb0f4035eb4d2e2c1a22cc6d36fe4b73e17d9d6848333ff03a9";

/// On-chain account address of the standard Argent account for this key:
/// deployed with `salt = public key`, deployer `0`, calldata `[0, public_key, 1]`.
///
/// Class hash: Argent v0.4.0 (`0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f`)
/// Contract version: 0.4.0 (get_version returns `{ major: 0, minor: 4, patch: 0 }`)
pub const ARGENT_ACCOUNT_ADDRESS: &str =
    "0x06bB92aC7bd2ba6922e497F8B9CCF4357559e3f3896396D5834D8A0B1ce1fC0E";

/// Argent v0.4.0 (Cairo 1) class hash.
pub const ARGENT_V040_CLASS_HASH: &str =
    "0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f";

// -- Braavos expected values --------------------------------------------------

/// The passphrase shown in the Braavos UI. **NOT used in BIP-39 seed generation.**
/// Braavos uses passphrase for wallet-level encryption only.
pub const BRAAVOS_PASSPHRASE: &str = "test-test-test";

/// Stark private key derived via Braavos's direct derivation.
///
/// Derivation: mnemonic → m/44'/9004'/0'/0/0 → grindKey (no passphrase in BIP-39)
pub const BRAAVOS_PRIVATE_KEY: &str =
    "0x04fc62347709307c23db0d065f4fd0a0f717e84d963dac1ac1eed740625700c3";

/// Stark public key (x-coordinate) corresponding to `BRAAVOS_PRIVATE_KEY`.
pub const BRAAVOS_PUBLIC_KEY: &str =
    "0x2985b4b4b2a370bdded9810e0c6cf74f82caf31dba039d2ece7eb8b8b80bb5a";

/// On-chain account address. Fully derivable from mnemonic.
pub const BRAAVOS_ACCOUNT_ADDRESS: &str =
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
pub const BRAAVOS_BASE_CLASS_HASH: &str =
    "0x03d16c7a9a60b0593bd202f660a28c5d76e0403601d9ccc7e4fa253b6a70c201";
