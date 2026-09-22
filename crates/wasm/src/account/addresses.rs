//! Account contract address derivation and known class hashes.

use super::helpers::parse_felt;
use crate::error::from_sdk_result;
use krusty_kms::{AccountClass, ArgentAccount, ArgentCairo0, BraavosAccount};
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

/// Resolve the Argent preset for an optional class hash (default v0.4.0).
fn argent_account(class_hash: Option<String>) -> Result<ArgentAccount, JsValue> {
    match class_hash {
        Some(ref hash) => {
            let ch = parse_felt(hash)?;
            ArgentAccount::try_with_class_hash(ch)
                .map_err(|e| JsValue::from_str(&format!("Failed to derive Argent address: {e}")))
        }
        None => Ok(ArgentAccount::new()),
    }
}

/// Derive an Argent account contract address from a public key.
///
/// Uses the standard Argent deployment (salt = public key, Starknet-key owner,
/// no guardian). The constructor calldata follows the class version:
/// `[0, public_key, 1]` for v0.4.0 and v0.5.0, `[public_key, 0]` for v0.3.x;
/// `getAccountClassRegistry()` publishes the convention next to each class.
///
/// This is the only Argent deployment a seed phrase reproduces on its own. An
/// account deployed with a guardian has a different address that discovery
/// cannot enumerate; once its address is known, feed its `DEPLOY_ACCOUNT`
/// fields to `inspectAccountDeployment`, or take the guardian from that
/// calldata and use `deriveArgentAccountAddressWithGuardian`.
///
/// # Arguments
/// * `public_key` - The Stark public key (hex string)
/// * `class_hash` - Optional class hash (hex string). Defaults to the Argent
///   v0.4.0 class hash; every class in `getAccountClassRegistry()` with family
///   `argent` and a `constructor` is accepted. A class hash that is not a
///   recognised Argent class is rejected: its constructor layout is unknown,
///   so any address derived for it could be undeployable.
///
/// # Returns
/// The derived account contract address as hex string
#[wasm_bindgen(js_name = "deriveArgentAccountAddress")]
pub fn derive_argent_account_address(
    public_key: &str,
    class_hash: Option<String>,
) -> Result<String, JsValue> {
    let pk = parse_felt(public_key)?;
    let address = argent_account(class_hash)?
        .calculate_address(&pk, krusty_kms::SaltPolicy::PublicKey)
        .map_err(|e| JsValue::from_str(&format!("Failed to derive Argent address: {e}")))?;
    Ok(format!("{:#x}", address))
}

/// Derive an Argent account contract address for an owner **with** a
/// Starknet-key guardian.
///
/// Salt = public key; constructor calldata `[public_key, guardian]` for
/// v0.3.x and `[0, public_key, 0, 0, guardian]` for v0.4.0 and v0.5.0. The
/// guardian is per-account and not derived from the seed, so this cannot find
/// accounts from a phrase. It verifies an account whose address is already
/// known: take the guardian from that account's `DEPLOY_ACCOUNT` calldata and
/// compare the result with the address. Only the deploy-time guardian fixes
/// the address; an account's current guardian (`get_guardian`) can have been
/// changed or removed since and reproduces nothing.
///
/// # Arguments
/// * `public_key` - The owner's Stark public key (hex string)
/// * `guardian_public_key` - The guardian's Stark public key at deployment
///   (hex string). `"0x0"` means no guardian and gives the same address as
///   `deriveArgentAccountAddress`
/// * `class_hash` - Optional class hash, as for `deriveArgentAccountAddress`
///
/// # Returns
/// The derived account contract address as hex string
#[wasm_bindgen(js_name = "deriveArgentAccountAddressWithGuardian")]
pub fn derive_argent_account_address_with_guardian(
    public_key: &str,
    guardian_public_key: &str,
    class_hash: Option<String>,
) -> Result<String, JsValue> {
    let pk = parse_felt(public_key)?;
    let guardian = parse_felt(guardian_public_key)?;
    let address = argent_account(class_hash)?
        .calculate_address_with_guardian(&pk, &guardian)
        .map_err(|e| JsValue::from_str(&format!("Failed to derive Argent address: {e}")))?;
    Ok(format!("{:#x}", address))
}

/// Derive a Braavos account contract address from a public key.
///
/// Uses the Braavos base-account deployment: salt = public key, constructor
/// calldata `[public_key]`. Braavos accounts are deployed with a **base**
/// class and upgrade themselves to an **implementation** class in the same
/// transaction, so the address is fixed by the base class alone and the class
/// an account runs today (`starknet_getClassHashAt`) never reproduces it.
///
/// # Arguments
/// * `public_key` - The Stark public key (hex string)
/// * `class_hash` - Optional base class hash (hex string). Defaults to the
///   current base class (v1.1.0 and later); the v1.0.0 base class is the other
///   accepted value, see `getAccountClassRegistry()` (family `braavos`, role
///   `deployment`). A known implementation class or an unrecognised class hash
///   is rejected rather than deriving an address no deployment produces.
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
            BraavosAccount::try_with_class_hash(ch)
                .map_err(|e| JsValue::from_str(&format!("Failed to derive Braavos address: {e}")))?
        }
        None => BraavosAccount::new(),
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
/// A flat map of class hashes by family and version label. It does not say
/// which role a class plays, and that distinction matters: an address is fixed
/// by the class an account was **deployed** with, while the class it **runs**
/// today (what a signer must accept) is a different one for every Braavos
/// account. Prefer `getAccountClassRegistry()`, which labels every entry by
/// role; this export is kept for callers that rely on its shape.
///
/// Braavos keys: `"1.0.0"` is the historical name of the base (deployment)
/// class introduced in v1.1.0 and still current; `"base-1.0.0"` is the v1.0.0
/// base class; `"legacy"` is the v1.0.0 account implementation and
/// `"account-1.1.0"` / `"account-1.2.0"` the later ones. Only the two base
/// classes derive addresses.
///
/// # Returns
/// JSON string with nested object:
/// `{ oz: { ... }, argent: { ... }, argent_legacy: { ... }, braavos: { ... } }`
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
            "0.5.0": ArgentAccount::CLASS_HASH_V050,
            "0.4.0": ArgentAccount::CLASS_HASH,
            "0.3.1": ArgentAccount::CLASS_HASH_V031,
            "0.3.0": ArgentAccount::CLASS_HASH_V030
        },
        "argent_legacy": {
            "proxy": ArgentCairo0::PROXY_CLASS_HASH,
            "0.2.4": ArgentCairo0::IMPL_CLASS_HASH_V024,
            "0.2.3": ArgentCairo0::IMPL_CLASS_HASH_V023,
            "0.2.2": ArgentCairo0::IMPL_CLASS_HASH_V022,
            "0.2.1": ArgentCairo0::IMPL_CLASS_HASH_V021
        },
        "braavos": {
            "1.0.0": BraavosAccount::CLASS_HASH,
            "base-1.0.0": BraavosAccount::BASE_CLASS_HASH_V100,
            "legacy": BraavosAccount::LEGACY_CLASS_HASH,
            "account-1.1.0": BraavosAccount::ACCOUNT_CLASS_HASH_V110,
            "account-1.2.0": BraavosAccount::ACCOUNT_CLASS_HASH_V120
        }
    });
    hashes.to_string()
}
