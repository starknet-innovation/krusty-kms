//! Candidate and keypair generation from a mnemonic. Performs no network I/O.

use super::types::{CandidateAccount, DerivationType, DerivedKeypair, WalletType};
use super::MAX_DISCOVERY_INDEX;
use crate::account::calculate_contract_address;
use crate::account_class::{AccountClass, ArgentAccount, ArgentCairo0, BraavosAccount, SaltPolicy};
use crate::derivation::{derive_argent_legacy_private_key, derive_private_key_with_coin_type};
use crate::mnemonic::validate_mnemonic;
use crate::stark_signing::stark_public_key;
use krusty_kms_common::{KmsError, Result};
use starknet_types_core::felt::Felt;

/// OpenZeppelin v3.0.0 class hash (identical on Mainnet and Sepolia).
const OZ_V300: &str = "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381";

/// Starknet coin type for BIP-44 derivation (SNIP-44).
const STARKNET_COIN_TYPE: u32 = 9004;

/// Format a Felt as a `0x`-prefixed lowercase hex string.
fn felt_hex(f: &Felt) -> String {
    format!("{:#x}", f)
}

/// Entry-point validation shared by every discovery scan: the index bound is
/// checked before the mnemonic so an oversized request does no secret work.
pub(super) fn validate_discovery_inputs(mnemonic: &str, max_index: u32) -> Result<()> {
    if max_index > MAX_DISCOVERY_INDEX {
        return Err(KmsError::InvalidDerivationPath(format!(
            "max_index {max_index} exceeds the discovery limit of {MAX_DISCOVERY_INDEX}"
        )));
    }
    validate_mnemonic(mnemonic)
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
    validate_discovery_inputs(mnemonic, max_index)?;

    // Two keypairs per index. The bound above keeps this in range; the checked
    // multiply makes "never panic on a caller-supplied size" hold locally.
    let capacity = (max_index as usize).checked_mul(2).unwrap_or(0);
    let mut keypairs = Vec::with_capacity(capacity);

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

/// One key scheme's material at one index, shared by every candidate built
/// from it.
struct DerivedKey<'a> {
    private_key: &'a Felt,
    public_key: &'a Felt,
    index: u32,
    path: &'a str,
}

impl DerivedKey<'_> {
    fn candidate(
        &self,
        wallet_type: WalletType,
        class_hash: &Felt,
        address: &Felt,
        class_version: &str,
    ) -> CandidateAccount {
        CandidateAccount {
            wallet_type,
            class_hash: felt_hex(class_hash),
            address: felt_hex(address),
            public_key: felt_hex(self.public_key),
            private_key: felt_hex(self.private_key),
            derivation_index: self.index,
            derivation_path: self.path.to_string(),
            class_version: class_version.to_string(),
        }
    }
}

/// Braavos: one candidate per base (deployment) class. Braavos accounts
/// upgrade to an implementation class in their deploy transaction, so the
/// class an account runs today never fixed its address and is not a
/// candidate; the registry keeps the two apart.
fn push_braavos_candidates(out: &mut Vec<CandidateAccount>, key: &DerivedKey<'_>) -> Result<()> {
    for class in BraavosAccount::known_classes()
        .into_iter()
        .filter(|class| class.is_deployment_class())
    {
        let address = BraavosAccount::with_class_hash(class.class_hash)
            .calculate_address(key.public_key, SaltPolicy::PublicKey)?;
        out.push(key.candidate(
            WalletType::Braavos,
            &class.class_hash,
            &address,
            &format!("base v{}", class.version),
        ));
    }
    Ok(())
}

/// Argent Cairo 1: every known class with its own constructor layout, under
/// whichever key scheme `wallet_type` names. The class a real account was
/// deployed with is not knowable from the seed, so all of them are tried.
fn push_argent_cairo1_candidates(
    out: &mut Vec<CandidateAccount>,
    wallet_type: WalletType,
    key: &DerivedKey<'_>,
) -> Result<()> {
    for (class_hash, version, layout) in ArgentAccount::known_classes() {
        let address = ArgentAccount::with_class_hash_and_layout(class_hash, layout)
            .calculate_address(key.public_key, SaltPolicy::PublicKey)?;
        out.push(key.candidate(wallet_type, &class_hash, &address, version));
    }
    Ok(())
}

/// OpenZeppelin v3.0.0 under both salt policies. The deploy/gateway flows
/// default to salt = public key (`SaltPolicy::PublicKey`), so recovery must
/// cover that variant or it misses accounts this project deployed itself;
/// salt = 0 is kept for externally-deployed OZ accounts.
fn push_oz_candidates(out: &mut Vec<CandidateAccount>, key: &DerivedKey<'_>) -> Result<()> {
    let oz_hash = Felt::from_hex(OZ_V300).expect("static OpenZeppelin class hash");
    for (salt, version) in [
        (*key.public_key, "v3.0.0 salt-pubkey"),
        (Felt::ZERO, "v3.0.0"),
    ] {
        let address = calculate_contract_address(&salt, &oz_hash, &[*key.public_key], &Felt::ZERO)?;
        out.push(key.candidate(WalletType::OpenZeppelin, &oz_hash, &address, version));
    }
    Ok(())
}

/// Argent Cairo 0: the proxy deployment class in front of each known
/// implementation, initialised with the owner key and no guardian.
fn push_argent_cairo0_candidates(
    out: &mut Vec<CandidateAccount>,
    key: &DerivedKey<'_>,
) -> Result<()> {
    let proxy = ArgentCairo0::proxy_class_hash();
    for (implementation, version) in ArgentCairo0::known_implementations() {
        let calldata = ArgentCairo0::constructor_calldata(&implementation, key.public_key);
        let address = calculate_contract_address(key.public_key, &proxy, &calldata, &Felt::ZERO)?;
        out.push(key.candidate(
            WalletType::ArgentCairo0,
            &proxy,
            &address,
            &format!("proxy+v{version}"),
        ));
    }
    Ok(())
}

/// Generate all candidate account addresses for a mnemonic.
///
/// Iterates through derivation indices `0..max_index` and generates candidate
/// addresses for every known wallet type and deployment class combination:
///
/// - **Braavos**: direct derivation, every base (deployment) class
/// - **Argent**: direct derivation, every Cairo 1 class (v0.5.0 down to v0.3.0)
/// - **Argent legacy**: double derivation (via ETH key), the same Cairo 1 classes
/// - **Argent Cairo 0**: double derivation, proxy + implementation pattern
/// - **OpenZeppelin**: direct derivation, OZ v3.0.0 with both salt policies
///   (salt = public key matching this project's deploy flow, and salt = 0)
///
/// Every candidate assumes a guardian-less deployment salted with the public
/// key. An account deployed with a guardian, a non-Starknet owner or a
/// server-assigned salt exists on chain but is not among these candidates;
/// [`crate::inspect_deployment`] tells the two apart once the deploy
/// transaction is known.
///
/// Does NOT hit the network. Returns all mathematically possible addresses.
/// Use with an RPC provider to filter to actually deployed accounts. The class
/// a found account runs today is an implementation class that may differ from
/// the candidate's deployment class; see [`crate::lookup_account_class`].
pub fn generate_candidates(mnemonic: &str, max_index: u32) -> Result<Vec<CandidateAccount>> {
    validate_discovery_inputs(mnemonic, max_index)?;

    let mut candidates = Vec::new();

    for index in 0..max_index {
        // (a) Direct derivation — shared by Braavos, new Argent, OZ
        let direct_pk =
            derive_private_key_with_coin_type(mnemonic, index, 0, STARKNET_COIN_TYPE, None)?;
        let direct_pubk = stark_public_key(&direct_pk)?;
        let direct_path = format!("m/44'/9004'/0'/0/{index}");
        let direct = DerivedKey {
            private_key: &direct_pk,
            public_key: &direct_pubk,
            index,
            path: &direct_path,
        };
        push_braavos_candidates(&mut candidates, &direct)?;
        push_argent_cairo1_candidates(&mut candidates, WalletType::Argent, &direct)?;
        push_oz_candidates(&mut candidates, &direct)?;

        // (b) Legacy double derivation — old Argent
        let legacy_pk = derive_argent_legacy_private_key(mnemonic, index, 0)?;
        let legacy_pubk = stark_public_key(&legacy_pk)?;
        let legacy_path = format!("m/44'/60'/0'/0/0 -> m/44'/9004'/0'/0/{index}");
        let legacy = DerivedKey {
            private_key: &legacy_pk,
            public_key: &legacy_pubk,
            index,
            path: &legacy_path,
        };
        push_argent_cairo1_candidates(&mut candidates, WalletType::ArgentLegacy, &legacy)?;
        push_argent_cairo0_candidates(&mut candidates, &legacy)?;
    }

    Ok(candidates)
}
