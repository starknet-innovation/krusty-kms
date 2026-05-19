//! WASM bindings for Starknet transaction hash computation.
//!
//! Provides JavaScript-accessible functions that wrap the deterministic
//! transaction hash routines in `krusty_kms::tx_hash` for invoke, deploy
//! account, and declare transactions (v1/v2/v3), plus SNIP-12 typed data
//! message hashing.

use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a hex-encoded string into a `Felt`.
fn parse_felt(hex: &str) -> Result<Felt, JsValue> {
    Felt::from_hex(hex).map_err(|e| JsValue::from_str(&format!("Invalid hex: {e}")))
}

/// Parse a slice of hex strings into a `Vec<Felt>`.
fn parse_felts(hexes: &[String]) -> Result<Vec<Felt>, JsValue> {
    hexes.iter().map(|s| parse_felt(s)).collect()
}

/// Map a `u8` to the `DaMode` enum used by the KMS crate.
fn da_mode_from_u8(val: u8) -> Result<krusty_kms::tx_hash::DaMode, JsValue> {
    match val {
        0 => Ok(krusty_kms::tx_hash::DaMode::L1),
        1 => Ok(krusty_kms::tx_hash::DaMode::L2),
        _ => Err(JsValue::from_str("DA mode must be 0 (L1) or 1 (L2)")),
    }
}

// ---------------------------------------------------------------------------
// Serde structs for deserialising resource bounds from JS objects
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
struct ResourceBoundsInput {
    #[serde(alias = "l1Gas")]
    l1_gas: ResourceBoundInput,
    #[serde(alias = "l2Gas")]
    l2_gas: ResourceBoundInput,
    #[serde(alias = "l1DataGas", default)]
    l1_data_gas: Option<ResourceBoundInput>,
}

#[derive(Deserialize, Serialize)]
struct ResourceBoundInput {
    #[serde(alias = "maxAmount")]
    max_amount: String,
    #[serde(alias = "maxPricePerUnit")]
    max_price_per_unit: String,
}

impl ResourceBoundInput {
    fn to_resource_bounds(&self) -> Result<krusty_kms::tx_hash::ResourceBounds, JsValue> {
        let max_amount: u64 = self
            .max_amount
            .parse()
            .or_else(|_| u64::from_str_radix(self.max_amount.trim_start_matches("0x"), 16))
            .map_err(|e| JsValue::from_str(&format!("Invalid max_amount: {e}")))?;
        let max_price_per_unit: u128 = self
            .max_price_per_unit
            .parse()
            .or_else(|_| u128::from_str_radix(self.max_price_per_unit.trim_start_matches("0x"), 16))
            .map_err(|e| JsValue::from_str(&format!("Invalid max_price_per_unit: {e}")))?;
        Ok(krusty_kms::tx_hash::ResourceBounds {
            max_amount,
            max_price_per_unit,
        })
    }
}

/// Parse the `tip` field (hex or decimal string) into a `u64`.
fn parse_tip(tip: &str) -> Result<u64, JsValue> {
    tip.parse::<u64>()
        .or_else(|_| u64::from_str_radix(tip.trim_start_matches("0x"), 16))
        .map_err(|e| JsValue::from_str(&format!("Invalid tip: {e}")))
}

// ---------------------------------------------------------------------------
// WASM bindings — Invoke
// ---------------------------------------------------------------------------

/// Compute the hash of an invoke transaction (v1).
///
/// All felt arguments are hex strings (e.g. `"0x1234"`).
#[wasm_bindgen(js_name = "computeInvokeTransactionHashV1")]
pub fn compute_invoke_transaction_hash_v1(
    sender_address: &str,
    calldata: Vec<String>,
    max_fee: &str,
    chain_id: &str,
    nonce: &str,
) -> Result<String, JsValue> {
    let sender = parse_felt(sender_address)?;
    let cd = parse_felts(&calldata)?;
    let fee = parse_felt(max_fee)?;
    let chain = parse_felt(chain_id)?;
    let n = parse_felt(nonce)?;

    let hash = krusty_kms::tx_hash::compute_invoke_v1_hash(&sender, &cd, &fee, &chain, &n);
    Ok(format!("{:#x}", hash))
}

/// Compute the hash of an invoke transaction (v3).
#[wasm_bindgen(js_name = "computeInvokeTransactionHashV3")]
#[allow(clippy::too_many_arguments)]
pub fn compute_invoke_transaction_hash_v3(
    sender_address: &str,
    calldata: Vec<String>,
    chain_id: &str,
    nonce: &str,
    tip: &str,
    resource_bounds: JsValue,
    paymaster_data: Vec<String>,
    nonce_data_availability_mode: u8,
    fee_data_availability_mode: u8,
    account_deployment_data: Vec<String>,
    proof_facts: Option<Vec<String>>,
) -> Result<String, JsValue> {
    let sender = parse_felt(sender_address)?;
    let cd = parse_felts(&calldata)?;
    let chain = parse_felt(chain_id)?;
    let n = parse_felt(nonce)?;
    let tip_val = parse_tip(tip)?;
    let pm_data = parse_felts(&paymaster_data)?;
    let acct_deploy_data = parse_felts(&account_deployment_data)?;
    let proof_facts = match proof_facts {
        Some(values) => parse_felts(&values)?,
        None => Vec::new(),
    };
    let nonce_da = da_mode_from_u8(nonce_data_availability_mode)?;
    let fee_da = da_mode_from_u8(fee_data_availability_mode)?;

    let bounds: ResourceBoundsInput = serde_wasm_bindgen::from_value(resource_bounds)
        .map_err(|e| JsValue::from_str(&format!("Invalid resource bounds: {e}")))?;
    let l1_gas = bounds.l1_gas.to_resource_bounds()?;
    let l2_gas = bounds.l2_gas.to_resource_bounds()?;
    let l1_data_gas = match bounds.l1_data_gas {
        Some(ref b) => b.to_resource_bounds()?,
        None => krusty_kms::tx_hash::ResourceBounds::zero(),
    };

    let hash = krusty_kms::tx_hash::compute_invoke_v3_hash_with_proof_facts(
        &sender,
        &cd,
        &chain,
        &n,
        &acct_deploy_data,
        tip_val,
        &l1_gas,
        &l2_gas,
        &l1_data_gas,
        &pm_data,
        nonce_da,
        fee_da,
        &proof_facts,
    );
    Ok(format!("{:#x}", hash))
}

// ---------------------------------------------------------------------------
// WASM bindings — Deploy Account
// ---------------------------------------------------------------------------

/// Compute the hash of a deploy account transaction (v1).
#[wasm_bindgen(js_name = "computeDeployAccountTransactionHashV1")]
#[allow(clippy::too_many_arguments)]
pub fn compute_deploy_account_transaction_hash_v1(
    contract_address: &str,
    class_hash: &str,
    constructor_calldata: Vec<String>,
    salt: &str,
    max_fee: &str,
    chain_id: &str,
    nonce: &str,
) -> Result<String, JsValue> {
    let addr = parse_felt(contract_address)?;
    let cls = parse_felt(class_hash)?;
    let cd = parse_felts(&constructor_calldata)?;
    let s = parse_felt(salt)?;
    let fee = parse_felt(max_fee)?;
    let chain = parse_felt(chain_id)?;
    let n = parse_felt(nonce)?;

    let hash =
        krusty_kms::tx_hash::compute_deploy_account_v1_hash(&addr, &cls, &cd, &s, &fee, &chain, &n);
    Ok(format!("{:#x}", hash))
}

/// Compute the hash of a deploy account transaction (v3).
#[wasm_bindgen(js_name = "computeDeployAccountTransactionHashV3")]
#[allow(clippy::too_many_arguments)]
pub fn compute_deploy_account_transaction_hash_v3(
    contract_address: &str,
    class_hash: &str,
    constructor_calldata: Vec<String>,
    salt: &str,
    chain_id: &str,
    nonce: &str,
    tip: &str,
    resource_bounds: JsValue,
    paymaster_data: Vec<String>,
    nonce_data_availability_mode: u8,
    fee_data_availability_mode: u8,
) -> Result<String, JsValue> {
    let addr = parse_felt(contract_address)?;
    let cls = parse_felt(class_hash)?;
    let cd = parse_felts(&constructor_calldata)?;
    let s = parse_felt(salt)?;
    let chain = parse_felt(chain_id)?;
    let n = parse_felt(nonce)?;
    let tip_val = parse_tip(tip)?;
    let pm_data = parse_felts(&paymaster_data)?;
    let nonce_da = da_mode_from_u8(nonce_data_availability_mode)?;
    let fee_da = da_mode_from_u8(fee_data_availability_mode)?;

    let bounds: ResourceBoundsInput = serde_wasm_bindgen::from_value(resource_bounds)
        .map_err(|e| JsValue::from_str(&format!("Invalid resource bounds: {e}")))?;
    let l1_gas = bounds.l1_gas.to_resource_bounds()?;
    let l2_gas = bounds.l2_gas.to_resource_bounds()?;
    let l1_data_gas = match bounds.l1_data_gas {
        Some(ref b) => b.to_resource_bounds()?,
        None => krusty_kms::tx_hash::ResourceBounds::zero(),
    };

    let hash = krusty_kms::tx_hash::compute_deploy_account_v3_hash(
        &addr,
        &cls,
        &cd,
        &s,
        &chain,
        &n,
        tip_val,
        &l1_gas,
        &l2_gas,
        &l1_data_gas,
        &pm_data,
        nonce_da,
        fee_da,
    );
    Ok(format!("{:#x}", hash))
}

// ---------------------------------------------------------------------------
// WASM bindings — Declare
// ---------------------------------------------------------------------------

/// Compute the hash of a declare transaction (v2).
#[wasm_bindgen(js_name = "computeDeclareTransactionHashV2")]
pub fn compute_declare_transaction_hash_v2(
    sender_address: &str,
    class_hash: &str,
    max_fee: &str,
    chain_id: &str,
    nonce: &str,
    compiled_class_hash: &str,
) -> Result<String, JsValue> {
    let sender = parse_felt(sender_address)?;
    let cls = parse_felt(class_hash)?;
    let fee = parse_felt(max_fee)?;
    let chain = parse_felt(chain_id)?;
    let n = parse_felt(nonce)?;
    let compiled = parse_felt(compiled_class_hash)?;

    let hash =
        krusty_kms::tx_hash::compute_declare_v2_hash(&sender, &cls, &fee, &chain, &n, &compiled);
    Ok(format!("{:#x}", hash))
}

/// Compute the hash of a declare transaction (v3).
#[wasm_bindgen(js_name = "computeDeclareTransactionHashV3")]
#[allow(clippy::too_many_arguments)]
pub fn compute_declare_transaction_hash_v3(
    sender_address: &str,
    class_hash: &str,
    chain_id: &str,
    nonce: &str,
    compiled_class_hash: &str,
    tip: &str,
    resource_bounds: JsValue,
    paymaster_data: Vec<String>,
    nonce_data_availability_mode: u8,
    fee_data_availability_mode: u8,
    account_deployment_data: Vec<String>,
) -> Result<String, JsValue> {
    let sender = parse_felt(sender_address)?;
    let cls = parse_felt(class_hash)?;
    let chain = parse_felt(chain_id)?;
    let n = parse_felt(nonce)?;
    let compiled = parse_felt(compiled_class_hash)?;
    let tip_val = parse_tip(tip)?;
    let pm_data = parse_felts(&paymaster_data)?;
    let acct_deploy_data = parse_felts(&account_deployment_data)?;
    let nonce_da = da_mode_from_u8(nonce_data_availability_mode)?;
    let fee_da = da_mode_from_u8(fee_data_availability_mode)?;

    let bounds: ResourceBoundsInput = serde_wasm_bindgen::from_value(resource_bounds)
        .map_err(|e| JsValue::from_str(&format!("Invalid resource bounds: {e}")))?;
    let l1_gas = bounds.l1_gas.to_resource_bounds()?;
    let l2_gas = bounds.l2_gas.to_resource_bounds()?;
    let l1_data_gas = match bounds.l1_data_gas {
        Some(ref b) => b.to_resource_bounds()?,
        None => krusty_kms::tx_hash::ResourceBounds::zero(),
    };

    let hash = krusty_kms::tx_hash::compute_declare_v3_hash(
        &sender,
        &cls,
        &compiled,
        &chain,
        &n,
        tip_val,
        &l1_gas,
        &l2_gas,
        &l1_data_gas,
        &pm_data,
        nonce_da,
        fee_da,
        &acct_deploy_data,
    );
    Ok(format!("{:#x}", hash))
}

// ---------------------------------------------------------------------------
// WASM bindings — Typed data (SNIP-12)
// ---------------------------------------------------------------------------

/// Compute the SNIP-12 typed data message hash.
///
/// # Arguments
/// * `typed_data_json` - JSON string conforming to the SNIP-12 typed data schema.
/// * `account_address` - Hex-encoded Starknet account address.
///
/// # Returns
/// The message hash as a hex string.
#[wasm_bindgen(js_name = "computeTypedDataMessageHash")]
pub fn compute_typed_data_message_hash(
    typed_data_json: &str,
    account_address: &str,
) -> Result<String, JsValue> {
    let account = parse_felt(account_address)?;
    let hash = krusty_kms::compute_typed_data_message_hash(typed_data_json, &account)
        .map_err(|e| JsValue::from_str(&format!("Typed data hash error: {e}")))?;
    Ok(format!("{:#x}", hash))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_felt_valid() {
        assert!(parse_felt("0x1").is_ok());
        assert!(parse_felt("0xdeadbeef").is_ok());
        assert!(parse_felt("0x0").is_ok());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_parse_felt_invalid() {
        assert!(parse_felt("not_hex").is_err());
        assert!(parse_felt("").is_err());
    }

    #[test]
    fn test_parse_felts() {
        let inputs = vec!["0x1".to_string(), "0x2".to_string(), "0x3".to_string()];
        let result = parse_felts(&inputs);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[test]
    fn test_da_mode_from_u8() {
        assert!(da_mode_from_u8(0).is_ok());
        assert!(da_mode_from_u8(1).is_ok());
        #[cfg(target_arch = "wasm32")]
        {
            assert!(da_mode_from_u8(2).is_err());
            assert!(da_mode_from_u8(255).is_err());
        }
    }

    #[test]
    fn test_parse_tip() {
        assert_eq!(parse_tip("0").unwrap(), 0);
        assert_eq!(parse_tip("100").unwrap(), 100);
        assert_eq!(parse_tip("0xff").unwrap(), 255);
        #[cfg(target_arch = "wasm32")]
        {
            assert!(parse_tip("not_a_number").is_err());
        }
    }

    #[test]
    fn test_compute_typed_data_message_hash_wasm() {
        let json = serde_json::json!({
            "types": {
                "StarknetDomain": [
                    { "name": "name", "type": "shortstring" },
                    { "name": "version", "type": "shortstring" },
                    { "name": "chainId", "type": "shortstring" },
                    { "name": "revision", "type": "shortstring" }
                ],
                "Example": [
                    { "name": "value", "type": "felt" }
                ]
            },
            "primaryType": "Example",
            "domain": {
                "name": "StarkNet",
                "version": "1",
                "chainId": "SN_MAIN",
                "revision": "1"
            },
            "message": {
                "value": "0x1"
            }
        });

        let result = compute_typed_data_message_hash(&json.to_string(), "0x1234");
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(hash.starts_with("0x"));
        assert_ne!(hash, "0x0");

        // Must be deterministic.
        let result2 = compute_typed_data_message_hash(&json.to_string(), "0x1234");
        assert_eq!(hash, result2.unwrap());
    }

    #[test]
    fn test_typed_data_different_accounts() {
        let json = serde_json::json!({
            "types": {
                "StarknetDomain": [
                    { "name": "name", "type": "shortstring" },
                    { "name": "version", "type": "shortstring" },
                    { "name": "chainId", "type": "shortstring" },
                    { "name": "revision", "type": "shortstring" }
                ],
                "Example": [
                    { "name": "value", "type": "felt" }
                ]
            },
            "primaryType": "Example",
            "domain": {
                "name": "StarkNet",
                "version": "1",
                "chainId": "SN_MAIN",
                "revision": "1"
            },
            "message": {
                "value": "0x1"
            }
        });

        let hash1 = compute_typed_data_message_hash(&json.to_string(), "0x1111").unwrap();
        let hash2 = compute_typed_data_message_hash(&json.to_string(), "0x2222").unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_resource_bound_input_parsing() {
        let input = ResourceBoundInput {
            max_amount: "1000".to_string(),
            max_price_per_unit: "500".to_string(),
        };
        let rb = input.to_resource_bounds().unwrap();
        assert_eq!(rb.max_amount, 1000);
        assert_eq!(rb.max_price_per_unit, 500);
    }

    #[test]
    fn test_resource_bound_input_hex_parsing() {
        let input = ResourceBoundInput {
            max_amount: "0x3e8".to_string(),
            max_price_per_unit: "0x1f4".to_string(),
        };
        let rb = input.to_resource_bounds().unwrap();
        assert_eq!(rb.max_amount, 1000);
        assert_eq!(rb.max_price_per_unit, 500);
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;

    fn resource_bounds() -> JsValue {
        serde_wasm_bindgen::to_value(&ResourceBoundsInput {
            l1_gas: ResourceBoundInput {
                max_amount: "0x186a0".to_string(),
                max_price_per_unit: "0x5af3107a4000".to_string(),
            },
            l2_gas: ResourceBoundInput {
                max_amount: "0x0".to_string(),
                max_price_per_unit: "0x0".to_string(),
            },
            l1_data_gas: Some(ResourceBoundInput {
                max_amount: "0x0".to_string(),
                max_price_per_unit: "0x0".to_string(),
            }),
        })
        .unwrap()
    }

    fn compute_v3(proof_facts: Option<Vec<String>>) -> String {
        compute_invoke_transaction_hash_v3(
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            vec!["0x1".to_string(), "0x2".to_string(), "0x3".to_string()],
            "0x534e5f5345504f4c4941",
            "0x7",
            "0x0",
            resource_bounds(),
            vec![],
            0,
            0,
            vec![],
            proof_facts,
        )
        .unwrap()
    }

    #[wasm_bindgen_test]
    fn invoke_v3_empty_proof_facts_match_omitted_proof_facts() {
        assert_eq!(compute_v3(None), compute_v3(Some(vec![])));
    }

    #[wasm_bindgen_test]
    fn invoke_v3_proof_facts_match_starknet_js_10_0_2_vector() {
        let hash = compute_v3(Some(vec![
            "0x123".to_string(),
            "0x456".to_string(),
            "0x789".to_string(),
        ]));
        assert_eq!(
            hash,
            "0x15f5114c744e730be573a540456ad0a05d5f72964143b9839c57abc5ee7b31"
        );
    }
}
