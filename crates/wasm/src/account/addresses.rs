//! Account contract address derivation and known class hashes.

use super::helpers::parse_felt;
use crate::error::from_sdk_result;
use krusty_kms::AccountClass;
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

/// Derive an OpenZeppelin account contract address from a public key.
///
/// This calculates the counterfactual address for an OpenZeppelin account
/// using the standard contract address derivation formula.
///
/// # Arguments
/// * `public_key_x` - The x-coordinate of the Stark public key (hex string)
/// * `class_hash` - The OpenZeppelin account class hash (hex string)
/// * `salt` - Optional salt for address derivation (hex string; defaults to the public key)
///
/// # Returns
/// The derived account contract address as hex string
#[wasm_bindgen(js_name = "deriveOzAccountAddress")]
pub fn derive_oz_account_address(
    public_key_x: &str,
    class_hash: &str,
    salt: Option<String>,
) -> Result<String, JsValue> {
    let public_key = parse_felt(public_key_x)?;
    let class_hash_felt = parse_felt(class_hash)?;
    let salt_felt = match salt {
        Some(s) => Some(parse_felt(&s)?),
        None => None,
    };

    let address = from_sdk_result(krusty_kms::derive_oz_account_address(
        &public_key,
        &class_hash_felt,
        salt_felt.as_ref(),
    ))
    .map_err(JsValue::from)?;

    Ok(format!("{:#x}", address))
}

/// Derive an Argent account contract address from a public key.
///
/// Uses the standard Argent deployment (salt = public key, Starknet-key owner,
/// no guardian). The constructor calldata layout follows the class version:
/// `[0, public_key, 1]` for v0.4.0 and `[public_key, 0]` for v0.3.x.
///
/// # Arguments
/// * `public_key` - The Stark public key (hex string)
/// * `class_hash` - Optional custom class hash (hex string). Defaults to the
///   standard Argent v0.4.0 class hash.
///
/// # Returns
/// The derived account contract address as hex string
#[wasm_bindgen(js_name = "deriveArgentAccountAddress")]
pub fn derive_argent_account_address(
    public_key: &str,
    class_hash: Option<String>,
) -> Result<String, JsValue> {
    let pk = parse_felt(public_key)?;
    let account = match class_hash {
        Some(ref hash) => {
            let ch = parse_felt(hash)?;
            krusty_kms::ArgentAccount::with_class_hash(ch)
        }
        None => krusty_kms::ArgentAccount::new(),
    };
    let address = account
        .calculate_address(&pk, krusty_kms::SaltPolicy::PublicKey)
        .map_err(|e| JsValue::from_str(&format!("Failed to derive Argent address: {e}")))?;
    Ok(format!("{:#x}", address))
}

/// Derive a Braavos account contract address from a public key.
///
/// Uses the standard Braavos constructor calldata format `(public_key)`.
///
/// # Arguments
/// * `public_key` - The Stark public key (hex string)
/// * `class_hash` - Optional custom class hash (hex string). Defaults to the
///   standard Braavos v1.0.0 class hash.
///
/// # Returns
/// The derived account contract address as hex string
#[wasm_bindgen(js_name = "deriveBraavosAccountAddress")]
pub fn derive_braavos_account_address(
    public_key: &str,
    class_hash: Option<String>,
) -> Result<String, JsValue> {
    let pk = parse_felt(public_key)?;
    let account = match class_hash {
        Some(ref hash) => {
            let ch = parse_felt(hash)?;
            krusty_kms::BraavosAccount::with_class_hash(ch)
        }
        None => krusty_kms::BraavosAccount::new(),
    };
    let address = account
        .calculate_address(&pk, krusty_kms::SaltPolicy::PublicKey)
        .map_err(|e| JsValue::from_str(&format!("Failed to derive Braavos address: {e}")))?;
    Ok(format!("{:#x}", address))
}

/// Calculate a Starknet contract address from deployment parameters.
///
/// Implements the standard contract address derivation formula using
/// `computeHashOnElements`.
///
/// # Arguments
/// * `salt` - Salt value (hex string)
/// * `class_hash` - Contract class hash (hex string)
/// * `constructor_calldata` - Array of hex strings for constructor calldata
/// * `deployer_address` - Deployer address (hex string, typically "0x0")
///
/// # Returns
/// The calculated contract address as hex string
#[wasm_bindgen(js_name = "calculateContractAddress")]
pub fn calculate_contract_address(
    address_salt: &str,
    class_hash: &str,
    constructor_calldata: Vec<String>,
    deployer_address: &str,
) -> Result<String, JsValue> {
    let salt_felt = parse_felt(address_salt)?;
    let class_hash_felt = parse_felt(class_hash)?;
    let deployer_felt = parse_felt(deployer_address)?;
    let calldata: Vec<Felt> = constructor_calldata
        .iter()
        .map(|s| parse_felt(s))
        .collect::<Result<Vec<_>, _>>()?;

    let address = krusty_kms::calculate_contract_address(
        &salt_felt,
        &class_hash_felt,
        &calldata,
        &deployer_felt,
    )
    .map_err(|e| JsValue::from_str(&format!("Failed to calculate contract address: {e}")))?;

    Ok(format!("{:#x}", address))
}

/// Get known account class hashes for common Starknet account implementations.
///
/// Returns a JSON string containing class hashes organized by account type
/// and version, covering OpenZeppelin, Argent, and Braavos accounts.
///
/// # Returns
/// JSON string with nested object: `{ oz: { ... }, argent: { ... }, braavos: { ... } }`
#[wasm_bindgen(js_name = "getAccountClassHashes")]
pub fn get_account_class_hashes() -> String {
    let hashes = serde_json::json!({
        "oz": {
            "3.0.0": {
                "SN_MAIN": "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381",
                "SN_SEPOLIA": "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381"
            }
        },
        "argent": {
            "0.4.0": krusty_kms::ArgentAccount::CLASS_HASH,
            "0.3.1": krusty_kms::ArgentAccount::CLASS_HASH_V031,
            "0.3.0": krusty_kms::ArgentAccount::CLASS_HASH_V030
        },
        "argent_legacy": {
            "proxy": "0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918",
            "0.2.3": "0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2",
            "0.2.2": "0x01a7820094feaf82d53f53f214b81292d717e7bb9a92bb2488092cd306f3993f",
            "0.2.1": "0x03e327de1c40540b98d05cbcb13552008e36f0ec8d61d46956d2f9752c294328",
            "0.2.0": "0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"
        },
        "braavos": {
            "1.0.0": krusty_kms::BraavosAccount::CLASS_HASH,
            "legacy": krusty_kms::BraavosAccount::LEGACY_CLASS_HASH
        }
    });
    hashes.to_string()
}
