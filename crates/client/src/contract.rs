//! TONGO contract interaction utilities.
//!
//! This module provides high-level functions for interacting with the TONGO contract
//! on Starknet, including querying account states and contract parameters.

use crate::types::{AccountState, CipherBalance};
use krusty_kms_common::Result;
use starknet_rust::core::types::{BlockId, BlockTag, FunctionCall};
use starknet_rust::core::utils::get_selector_from_name;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;
use starknet_types_core::curve::ProjectivePoint;
use std::sync::Arc;

// Type aliases to distinguish between starknet-rs and starknet-types-core Felt types
type StarknetRsFelt = starknet_rust::core::types::Felt;
type CoreFelt = starknet_types_core::felt::Felt;

/// Convert from starknet-types-core Felt to starknet-rs Felt.
fn core_felt_to_rs(felt: CoreFelt) -> StarknetRsFelt {
    StarknetRsFelt::from_bytes_be(&felt.to_bytes_be())
}

/// Convert from starknet-rs Felt to starknet-types-core Felt.
fn rs_felt_to_core(felt: StarknetRsFelt) -> CoreFelt {
    CoreFelt::from_bytes_be(&felt.to_bytes_be())
}

/// TONGO contract client for querying state and parameters.
pub struct TongoContract {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    address: StarknetRsFelt,
}

impl TongoContract {
    /// Create a new TONGO contract client.
    ///
    /// # Arguments
    /// * `provider` - JSON-RPC provider for Starknet
    /// * `address` - TONGO contract address (from starknet-types-core)
    pub fn new(provider: Arc<JsonRpcClient<HttpTransport>>, address: CoreFelt) -> Self {
        Self {
            provider,
            address: core_felt_to_rs(address),
        }
    }

    /// Query the account state for a given public key.
    ///
    /// Returns the encrypted balance, pending balance, and nonce.
    ///
    /// # Cyclomatic Complexity: 2
    pub async fn get_state(&self, public_key: &ProjectivePoint) -> Result<AccountState> {
        let affine = public_key.to_affine().map_err(|_| {
            krusty_kms_common::KmsError::CryptoError("Invalid public key".to_string())
        })?;

        // Prepare calldata: [public_key_x, public_key_y]
        // Convert from CoreFelt to StarknetRsFelt
        let calldata = vec![core_felt_to_rs(affine.x()), core_felt_to_rs(affine.y())];

        // Call get_state(public_key: StarkPoint) -> AccountState
        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: get_selector_from_name("get_state")
                        .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
                    calldata,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| krusty_kms_common::KmsError::RpcError(e.to_string()))?;

        // Parse response: AccountState { balance: CipherBalance, pending: CipherBalance, nonce: felt252 }
        // CipherBalance is { L: StarkPoint, R: StarkPoint }
        // Expected response: [L.x, L.y, R.x, R.y, pending_L.x, pending_L.y, pending_R.x, pending_R.y, nonce]
        if result.len() < 9 {
            return Err(krusty_kms_common::KmsError::DeserializationError(format!(
                "Expected 9 felts for AccountState, got {}",
                result.len()
            )));
        }

        // Deserialize balance (convert from StarknetRsFelt to CoreFelt)
        let balance_l =
            ProjectivePoint::from_affine(rs_felt_to_core(result[0]), rs_felt_to_core(result[1]))
                .map_err(|_| {
                    krusty_kms_common::KmsError::DeserializationError(
                        "Invalid balance.L point".to_string(),
                    )
                })?;
        let balance_r =
            ProjectivePoint::from_affine(rs_felt_to_core(result[2]), rs_felt_to_core(result[3]))
                .map_err(|_| {
                    krusty_kms_common::KmsError::DeserializationError(
                        "Invalid balance.R point".to_string(),
                    )
                })?;

        // Deserialize pending
        let pending_l =
            ProjectivePoint::from_affine(rs_felt_to_core(result[4]), rs_felt_to_core(result[5]))
                .map_err(|_| {
                    krusty_kms_common::KmsError::DeserializationError(
                        "Invalid pending.L point".to_string(),
                    )
                })?;
        let pending_r =
            ProjectivePoint::from_affine(rs_felt_to_core(result[6]), rs_felt_to_core(result[7]))
                .map_err(|_| {
                    krusty_kms_common::KmsError::DeserializationError(
                        "Invalid pending.R point".to_string(),
                    )
                })?;

        // Deserialize nonce
        let nonce = rs_felt_to_core(result[8]);

        Ok(AccountState {
            balance: CipherBalance {
                l: balance_l,
                r: balance_r,
            },
            pending: CipherBalance {
                l: pending_l,
                r: pending_r,
            },
            nonce,
        })
    }

    /// Get the ERC20 token rate (how many ERC20 tokens per TONGO unit).
    ///
    /// # Cyclomatic Complexity: 1
    pub async fn get_rate(&self) -> Result<u128> {
        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: get_selector_from_name("get_rate")
                        .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| krusty_kms_common::KmsError::RpcError(e.to_string()))?;

        if result.is_empty() {
            return Err(krusty_kms_common::KmsError::DeserializationError(
                "Empty response from get_rate".to_string(),
            ));
        }

        // Convert felt to u128
        let bytes = result[0].to_bytes_be();
        let mut u128_bytes = [0u8; 16];
        u128_bytes.copy_from_slice(&bytes[16..32]);
        Ok(u128::from_be_bytes(u128_bytes))
    }

    /// Get the bit size used for range proofs.
    ///
    /// # Cyclomatic Complexity: 1
    pub async fn get_bit_size(&self) -> Result<u32> {
        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: get_selector_from_name("get_bit_size")
                        .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| krusty_kms_common::KmsError::RpcError(e.to_string()))?;

        if result.is_empty() {
            return Err(krusty_kms_common::KmsError::DeserializationError(
                "Empty response from get_bit_size".to_string(),
            ));
        }

        // Convert felt to u32
        let bytes = result[0].to_bytes_be();
        let mut u32_bytes = [0u8; 4];
        u32_bytes.copy_from_slice(&bytes[28..32]);
        Ok(u32::from_be_bytes(u32_bytes))
    }

    /// Get the ERC20 token contract address.
    ///
    /// # Cyclomatic Complexity: 1
    pub async fn get_erc20(&self) -> Result<CoreFelt> {
        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: get_selector_from_name("ERC20")
                        .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| krusty_kms_common::KmsError::RpcError(e.to_string()))?;

        if result.is_empty() {
            return Err(krusty_kms_common::KmsError::DeserializationError(
                "Empty response from ERC20".to_string(),
            ));
        }

        Ok(rs_felt_to_core(result[0]))
    }

    /// Deserialize a CipherBalance from 4 consecutive felts `[L.x, L.y, R.x, R.y]`.
    fn parse_cipher_balance(felts: &[StarknetRsFelt]) -> Result<CipherBalance> {
        if felts.len() < 4 {
            return Err(krusty_kms_common::KmsError::DeserializationError(format!(
                "Expected 4 felts for CipherBalance, got {}",
                felts.len()
            )));
        }
        let l = ProjectivePoint::from_affine(
            rs_felt_to_core(felts[0]),
            rs_felt_to_core(felts[1]),
        )
        .map_err(|_| {
            krusty_kms_common::KmsError::DeserializationError("Invalid L point".to_string())
        })?;
        let r = ProjectivePoint::from_affine(
            rs_felt_to_core(felts[2]),
            rs_felt_to_core(felts[3]),
        )
        .map_err(|_| {
            krusty_kms_common::KmsError::DeserializationError("Invalid R point".to_string())
        })?;
        Ok(CipherBalance { l, r })
    }

    /// Query the encrypted balance for a given public key.
    pub async fn get_balance(&self, public_key: &ProjectivePoint) -> Result<CipherBalance> {
        let affine = public_key.to_affine().map_err(|_| {
            krusty_kms_common::KmsError::CryptoError("Invalid public key".to_string())
        })?;

        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: get_selector_from_name("get_balance")
                        .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
                    calldata: vec![core_felt_to_rs(affine.x()), core_felt_to_rs(affine.y())],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| krusty_kms_common::KmsError::RpcError(e.to_string()))?;

        Self::parse_cipher_balance(&result)
    }

    /// Query the encrypted pending balance for a given public key.
    pub async fn get_pending(&self, public_key: &ProjectivePoint) -> Result<CipherBalance> {
        let affine = public_key.to_affine().map_err(|_| {
            krusty_kms_common::KmsError::CryptoError("Invalid public key".to_string())
        })?;

        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: get_selector_from_name("get_pending")
                        .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
                    calldata: vec![core_felt_to_rs(affine.x()), core_felt_to_rs(affine.y())],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| krusty_kms_common::KmsError::RpcError(e.to_string()))?;

        Self::parse_cipher_balance(&result)
    }

    /// Query the audit cipher balance for a given public key (CairoOption).
    pub async fn get_audit(
        &self,
        public_key: &ProjectivePoint,
    ) -> Result<Option<CipherBalance>> {
        let affine = public_key.to_affine().map_err(|_| {
            krusty_kms_common::KmsError::CryptoError("Invalid public key".to_string())
        })?;

        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: get_selector_from_name("get_audit")
                        .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
                    calldata: vec![core_felt_to_rs(affine.x()), core_felt_to_rs(affine.y())],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| krusty_kms_common::KmsError::RpcError(e.to_string()))?;

        if result.is_empty() {
            return Err(krusty_kms_common::KmsError::DeserializationError(
                "Empty response from get_audit".to_string(),
            ));
        }

        // CairoOption: [1] for None, [0, L.x, L.y, R.x, R.y] for Some
        if result[0] == StarknetRsFelt::ONE {
            return Ok(None);
        }

        if result[0] == StarknetRsFelt::ZERO {
            let cb = Self::parse_cipher_balance(&result[1..])?;
            return Ok(Some(cb));
        }

        Err(krusty_kms_common::KmsError::DeserializationError(
            "Invalid CairoOption variant".to_string(),
        ))
    }

    /// Query the nonce for a given public key.
    pub async fn get_nonce(&self, public_key: &ProjectivePoint) -> Result<CoreFelt> {
        let affine = public_key.to_affine().map_err(|_| {
            krusty_kms_common::KmsError::CryptoError("Invalid public key".to_string())
        })?;

        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: get_selector_from_name("get_nonce")
                        .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
                    calldata: vec![core_felt_to_rs(affine.x()), core_felt_to_rs(affine.y())],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| krusty_kms_common::KmsError::RpcError(e.to_string()))?;

        if result.is_empty() {
            return Err(krusty_kms_common::KmsError::DeserializationError(
                "Empty response from get_nonce".to_string(),
            ));
        }

        Ok(rs_felt_to_core(result[0]))
    }

    /// Query the contract owner address.
    pub async fn get_owner(&self) -> Result<CoreFelt> {
        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: get_selector_from_name("get_owner")
                        .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| krusty_kms_common::KmsError::RpcError(e.to_string()))?;

        if result.is_empty() {
            return Err(krusty_kms_common::KmsError::DeserializationError(
                "Empty response from get_owner".to_string(),
            ));
        }

        Ok(rs_felt_to_core(result[0]))
    }

    /// Get the auditor's public key if configured.
    ///
    /// Returns None if no auditor is set.
    ///
    /// # Cyclomatic Complexity: 2
    pub async fn auditor_key(&self) -> Result<Option<ProjectivePoint>> {
        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: get_selector_from_name("auditor_key")
                        .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| krusty_kms_common::KmsError::RpcError(e.to_string()))?;

        // Response is CairoOption<StarkPoint>
        // Some: [0, x, y]
        // None: [1]
        if result.is_empty() {
            return Err(krusty_kms_common::KmsError::DeserializationError(
                "Empty response from auditor_key".to_string(),
            ));
        }

        if result[0] == StarknetRsFelt::ONE {
            // None variant
            return Ok(None);
        }

        if result[0] == StarknetRsFelt::ZERO {
            // Some variant
            if result.len() < 3 {
                return Err(krusty_kms_common::KmsError::DeserializationError(
                    "Invalid CairoOption::Some response".to_string(),
                ));
            }

            let point = ProjectivePoint::from_affine(
                rs_felt_to_core(result[1]),
                rs_felt_to_core(result[2]),
            )
            .map_err(|_| {
                krusty_kms_common::KmsError::DeserializationError(
                    "Invalid auditor key point".to_string(),
                )
            })?;

            return Ok(Some(point));
        }

        Err(krusty_kms_common::KmsError::DeserializationError(
            "Invalid CairoOption variant".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    // Note: These tests require a running Starknet node with the TONGO contract deployed
    // See integration tests for full examples with actual RPC access
}
