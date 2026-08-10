//! WASM bindings for Starknet account candidate generation.
//!
//! Provides JavaScript-accessible APIs for discovering potential on-chain
//! accounts derived from a BIP-39 mnemonic. This is a pure cryptographic
//! operation — no network calls are made.
//!
//! # Security / threat model
//!
//! Default discovery APIs return **public-only** JSON (addresses, public keys,
//! derivation metadata). Private keys are omitted so casual logging, clipboard
//! use, or XSS cannot exfiltrate key material from discovery results.
//!
//! Explicit `*WithSecrets` APIs include private keys for wallet recovery flows
//! via [`CandidateAccount::with_secrets`] / [`DerivedKeypair::with_secrets`].
//! Treat those return values as secret: never log them, never send them to
//! untrusted JS contexts, and prefer keeping secrets in secure storage.

use krusty_kms::discovery::{CandidateAccount, DerivedKeypair};
use wasm_bindgen::prelude::*;

fn to_json_string<T: serde::Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {e}")))
}

/// Generate all candidate account addresses for a mnemonic (public-only).
///
/// Returns a JSON array of candidate accounts across all known wallet types
/// (Braavos, Argent, Argent Legacy, Argent Cairo 0, OpenZeppelin).
///
/// This is a pure cryptographic operation — no network calls are made.
/// Each candidate is a possible on-chain account address. To find which
/// ones are actually deployed, check each address via an RPC provider
/// (e.g., `provider.getClassHashAt(address)` in starknet.js).
///
/// # Security
///
/// Private keys are **not** included (default `CandidateAccount` Serialize).
/// Use [`generate_account_candidates_with_secrets`] when key material is required.
///
/// # Arguments
/// * `mnemonic` - BIP-39 mnemonic phrase (12 or 24 words)
/// * `max_index` - Maximum derivation index to scan (default: 5).
///   Higher values scan more potential accounts but take longer.
///
/// # Returns
/// JSON string: array of objects with fields:
/// - `walletType`: "Braavos" | "Argent" | "ArgentLegacy" | "ArgentCairo0" | "OpenZeppelin"
/// - `classHash`: hex string
/// - `address`: hex string
/// - `publicKey`: hex string
/// - `derivationIndex`: number
/// - `derivationPath`: string (e.g., "m/44'/9004'/0'/0/0")
/// - `classVersion`: string (e.g., "v0.4.0", "braavos-base")
///
/// # Example (JavaScript)
/// ```javascript
/// const candidates = JSON.parse(generateAccountCandidates(mnemonic, 3));
/// for (const c of candidates) {
///   const deployed = await provider.getClassHashAt(c.address).catch(() => null);
///   if (deployed) {
///     console.log(`Found ${c.walletType} account at ${c.address}`);
///   }
/// }
/// ```
#[wasm_bindgen(js_name = "generateAccountCandidates")]
pub fn generate_account_candidates(
    mnemonic: &str,
    max_index: Option<u32>,
) -> Result<String, JsValue> {
    let max = max_index.unwrap_or(5);
    let candidates = krusty_kms::discovery::generate_candidates(mnemonic, max)
        .map_err(|e| JsValue::from_str(&format!("Discovery failed: {e}")))?;

    to_json_string(&candidates)
}

/// Like [`generate_account_candidates`], but includes `privateKey` on each candidate.
///
/// # Security
///
/// **Opt-in secret API.** The returned JSON contains private keys. Do not log,
/// cache in localStorage, or pass through untrusted JavaScript. Prefer the
/// default public-only API for discovery scans.
#[wasm_bindgen(js_name = "generateAccountCandidatesWithSecrets")]
pub fn generate_account_candidates_with_secrets(
    mnemonic: &str,
    max_index: Option<u32>,
) -> Result<String, JsValue> {
    let max = max_index.unwrap_or(5);
    let candidates = krusty_kms::discovery::generate_candidates(mnemonic, max)
        .map_err(|e| JsValue::from_str(&format!("Discovery failed: {e}")))?;

    let with_secrets = candidates
        .iter()
        .map(CandidateAccount::with_secrets)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Discovery failed: {e}")))?;
    to_json_string(&with_secrets)
}

/// Generate a compact summary of candidate addresses grouped by derivation index.
///
/// Returns a JSON object where keys are derivation indices and values are
/// objects mapping wallet type to address. Useful for quick discovery without
/// needing the full candidate details. Never includes private keys.
///
/// # Returns
/// JSON string: `{ "0": { "Braavos": "0x...", "Argent": "0x...", ... }, "1": { ... } }`
#[wasm_bindgen(js_name = "generateAccountAddresses")]
pub fn generate_account_addresses(
    mnemonic: &str,
    max_index: Option<u32>,
) -> Result<String, JsValue> {
    let max = max_index.unwrap_or(5);
    let candidates = krusty_kms::discovery::generate_candidates(mnemonic, max)
        .map_err(|e| JsValue::from_str(&format!("Discovery failed: {e}")))?;

    // Group by (derivation_index, wallet_type) → take first address for each combo
    let mut grouped: std::collections::BTreeMap<u32, std::collections::BTreeMap<String, String>> =
        std::collections::BTreeMap::new();

    for c in &candidates {
        let index_map = grouped.entry(c.derivation_index).or_default();
        let type_name = format!("{:?}", c.wallet_type);
        // Only keep the first address per wallet type per index
        // (there may be multiple class hash variants)
        index_map
            .entry(type_name)
            .or_insert_with(|| c.address.clone());
    }

    to_json_string(&grouped)
}

/// Derive discovery keypairs for a mnemonic without computing addresses (public-only).
///
/// Returns one entry per derivation scheme per index:
/// - **Direct**: `m/44'/9004'/0'/0/{index}` — shared by Braavos, new Argent, OpenZeppelin
/// - **ArgentLegacy**: double derivation via ETH key — used by legacy Argent wallets
///
/// This is cheaper than `generateAccountCandidates` since it skips address computation.
/// Use these public keys to query external APIs (e.g., Argent's smart account
/// discovery endpoint) for accounts whose addresses can't be derived locally.
///
/// # Security
///
/// Private keys are **not** included. Use
/// [`derive_discovery_keypairs_with_secrets`] when key material is required.
///
/// # Returns
/// JSON string: array of objects with fields:
/// - `derivationType`: "Direct" | "ArgentLegacy"
/// - `publicKey`: hex string
/// - `derivationIndex`: number
/// - `derivationPath`: string
///
/// # Example (JavaScript)
/// ```javascript
/// const keypairs = JSON.parse(deriveDiscoveryKeypairs(mnemonic, 5));
///
/// // Use public keys to query Argent's smart account API
/// for (const kp of keypairs) {
///   const smartAccounts = await argentApi.findAccountsByPublicKey(kp.publicKey);
///   // smartAccounts contains addresses with server-provided salts
/// }
/// ```
#[wasm_bindgen(js_name = "deriveDiscoveryKeypairs")]
pub fn derive_discovery_keypairs(
    mnemonic: &str,
    max_index: Option<u32>,
) -> Result<String, JsValue> {
    let max = max_index.unwrap_or(5);
    let keypairs = krusty_kms::discovery::derive_discovery_keypairs(mnemonic, max)
        .map_err(|e| JsValue::from_str(&format!("Keypair derivation failed: {e}")))?;

    to_json_string(&keypairs)
}

/// Like [`derive_discovery_keypairs`], but includes `privateKey` on each entry.
///
/// # Security
///
/// **Opt-in secret API.** Treat the returned JSON as secret material.
#[wasm_bindgen(js_name = "deriveDiscoveryKeypairsWithSecrets")]
pub fn derive_discovery_keypairs_with_secrets(
    mnemonic: &str,
    max_index: Option<u32>,
) -> Result<String, JsValue> {
    let max = max_index.unwrap_or(5);
    let keypairs = krusty_kms::discovery::derive_discovery_keypairs(mnemonic, max)
        .map_err(|e| JsValue::from_str(&format!("Keypair derivation failed: {e}")))?;

    let with_secrets = keypairs
        .iter()
        .map(DerivedKeypair::with_secrets)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Keypair derivation failed: {e}")))?;
    to_json_string(&with_secrets)
}

/// Perform full account discovery in a single call (public-only).
///
/// Returns a JSON object with two fields:
/// - `keypairs`: array of public-only DerivedKeypair objects (for API-based smart account lookup)
/// - `candidates`: array of public-only CandidateAccount objects (for local address derivation)
///
/// This combines `deriveDiscoveryKeypairs` and `generateAccountCandidates` into
/// a single WASM call, eliminating one JS→WASM round-trip.
///
/// # Security
///
/// Private keys are **not** included. Use
/// [`discover_accounts_from_mnemonic_with_secrets`] when key material is required.
#[wasm_bindgen(js_name = "discoverAccountsFromMnemonic")]
pub fn discover_accounts_from_mnemonic(
    mnemonic: &str,
    max_index: Option<u32>,
) -> Result<String, JsValue> {
    let max = max_index.unwrap_or(5);
    let keypairs = krusty_kms::discovery::derive_discovery_keypairs(mnemonic, max)
        .map_err(|e| JsValue::from_str(&format!("Keypair derivation failed: {e}")))?;
    let candidates = krusty_kms::discovery::generate_candidates(mnemonic, max)
        .map_err(|e| JsValue::from_str(&format!("Candidate generation failed: {e}")))?;

    let result = serde_json::json!({
        "keypairs": keypairs,
        "candidates": candidates,
    });

    to_json_string(&result)
}

/// Like [`discover_accounts_from_mnemonic`], but includes private keys.
///
/// # Security
///
/// **Opt-in secret API.** Treat the returned JSON as secret material.
#[wasm_bindgen(js_name = "discoverAccountsFromMnemonicWithSecrets")]
pub fn discover_accounts_from_mnemonic_with_secrets(
    mnemonic: &str,
    max_index: Option<u32>,
) -> Result<String, JsValue> {
    let max = max_index.unwrap_or(5);
    let keypairs = krusty_kms::discovery::derive_discovery_keypairs(mnemonic, max)
        .map_err(|e| JsValue::from_str(&format!("Keypair derivation failed: {e}")))?;
    let candidates = krusty_kms::discovery::generate_candidates(mnemonic, max)
        .map_err(|e| JsValue::from_str(&format!("Candidate generation failed: {e}")))?;

    let keypairs_with_secrets = keypairs
        .iter()
        .map(DerivedKeypair::with_secrets)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Keypair derivation failed: {e}")))?;
    let candidates_with_secrets = candidates
        .iter()
        .map(CandidateAccount::with_secrets)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&format!("Candidate generation failed: {e}")))?;
    let result = serde_json::json!({
        "keypairs": keypairs_with_secrets,
        "candidates": candidates_with_secrets,
    });

    to_json_string(&result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    const TEST_MNEMONIC: &str =
        "person hunt couch artefact try half produce fatal large raw prison electric";

    #[wasm_bindgen_test]
    fn test_generate_account_candidates_public_only() {
        let result = generate_account_candidates(TEST_MNEMONIC, Some(1));
        assert!(result.is_ok());
        let json = result.unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert!(!parsed.is_empty(), "Should generate at least one candidate");

        // Verify camelCase field names
        let first = &parsed[0];
        assert!(first.get("walletType").is_some());
        assert!(first.get("classHash").is_some());
        assert!(first.get("address").is_some());
        assert!(first.get("publicKey").is_some());
        assert!(
            first.get("privateKey").is_none(),
            "default discovery API must omit privateKey"
        );
        assert!(first.get("derivationIndex").is_some());
        assert!(first.get("derivationPath").is_some());
        assert!(first.get("classVersion").is_some());

        // Verify snake_case names are NOT present
        assert!(first.get("wallet_type").is_none());
        assert!(first.get("class_hash").is_none());
        assert!(first.get("public_key").is_none());
        assert!(first.get("private_key").is_none());
        assert!(first.get("derivation_index").is_none());
        assert!(first.get("derivation_path").is_none());
        assert!(first.get("class_version").is_none());
    }

    #[wasm_bindgen_test]
    fn test_generate_account_candidates_with_secrets() {
        let result = generate_account_candidates_with_secrets(TEST_MNEMONIC, Some(1));
        assert!(result.is_ok());
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(!parsed.is_empty());
        let first = &parsed[0];
        assert!(first.get("privateKey").is_some());
        assert!(first.get("publicKey").is_some());
        assert!(first.get("address").is_some());
    }

    #[wasm_bindgen_test]
    fn test_generate_account_candidates_invalid_mnemonic() {
        let result = generate_account_candidates("not a valid mnemonic", Some(1));
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_generate_account_addresses_compact() {
        let result = generate_account_addresses(TEST_MNEMONIC, Some(1));
        assert!(result.is_ok());
        let json = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Should have key "0" for index 0
        assert!(parsed.get("0").is_some());
        // Compact path must never embed private key material
        assert!(!json.contains("privateKey"));
        assert!(!json.contains("private_key"));
    }

    #[wasm_bindgen_test]
    fn test_derive_discovery_keypairs_public_only() {
        let result = derive_discovery_keypairs(TEST_MNEMONIC, Some(1)).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert!(!parsed.is_empty());
        assert!(parsed[0].get("publicKey").is_some());
        assert!(parsed[0].get("privateKey").is_none());
    }

    #[wasm_bindgen_test]
    fn test_discover_accounts_public_only() {
        let result = discover_accounts_from_mnemonic(TEST_MNEMONIC, Some(1)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        let keypairs = parsed.get("keypairs").unwrap().as_array().unwrap();
        let candidates = parsed.get("candidates").unwrap().as_array().unwrap();
        assert!(!keypairs.is_empty());
        assert!(!candidates.is_empty());
        assert!(keypairs[0].get("privateKey").is_none());
        assert!(candidates[0].get("privateKey").is_none());
    }
}
