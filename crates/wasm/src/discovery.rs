//! WASM bindings for Starknet account candidate generation.
//!
//! Provides JavaScript-accessible APIs for discovering potential on-chain
//! accounts derived from a BIP-39 mnemonic. This is a pure cryptographic
//! operation — no network calls are made.

use wasm_bindgen::prelude::*;

/// Generate all candidate account addresses for a mnemonic.
///
/// Returns a JSON array of candidate accounts across all known wallet types
/// (Braavos, Argent, Argent Legacy, Argent Cairo 0, OpenZeppelin).
///
/// This is a pure cryptographic operation — no network calls are made.
/// Each candidate is a possible on-chain account address. To find which
/// ones are actually deployed, check each address via an RPC provider
/// (e.g., `provider.getClassHashAt(address)` in starknet.js).
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
/// - `privateKey`: hex string (handle with care!)
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

    serde_json::to_string(&candidates)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {e}")))
}

/// Generate a compact summary of candidate addresses grouped by derivation index.
///
/// Returns a JSON object where keys are derivation indices and values are
/// objects mapping wallet type to address. Useful for quick discovery without
/// needing the full candidate details.
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

    serde_json::to_string(&grouped)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {e}")))
}

/// Derive all unique keypairs for a mnemonic without computing addresses.
///
/// Returns one keypair per derivation scheme per index:
/// - **Direct**: `m/44'/9004'/0'/0/{index}` — shared by Braavos, new Argent, OpenZeppelin
/// - **ArgentLegacy**: double derivation via ETH key — used by legacy Argent wallets
///
/// This is cheaper than `generateAccountCandidates` since it skips address computation.
/// Use these public keys to query external APIs (e.g., Argent's smart account
/// discovery endpoint) for accounts whose addresses can't be derived locally.
///
/// # Returns
/// JSON string: array of objects with fields:
/// - `derivationType`: "Direct" | "ArgentLegacy"
/// - `publicKey`: hex string
/// - `privateKey`: hex string (handle with care!)
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

    serde_json::to_string(&keypairs)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {e}")))
}

/// Perform full account discovery in a single call.
///
/// Returns a JSON object with two fields:
/// - `keypairs`: array of DerivedKeypair objects (for API-based smart account lookup)
/// - `candidates`: array of CandidateAccount objects (for local address derivation)
///
/// This combines `deriveDiscoveryKeypairs` and `generateAccountCandidates` into
/// a single WASM call, eliminating one JS→WASM round-trip.
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

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_generate_account_candidates() {
        let result = generate_account_candidates(
            "person hunt couch artefact try half produce fatal large raw prison electric",
            Some(1),
        );
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
        assert!(first.get("privateKey").is_some());
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
    fn test_generate_account_candidates_invalid_mnemonic() {
        let result = generate_account_candidates("not a valid mnemonic", Some(1));
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_generate_account_addresses_compact() {
        let result = generate_account_addresses(
            "person hunt couch artefact try half produce fatal large raw prison electric",
            Some(1),
        );
        assert!(result.is_ok());
        let json = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Should have key "0" for index 0
        assert!(parsed.get("0").is_some());
    }
}
