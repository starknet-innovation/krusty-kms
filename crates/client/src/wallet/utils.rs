//! Wallet utility functions for Felt conversion and deployment checking.

use krusty_kms_common::{KmsError, Result};
use starknet_rust::core::types::{BlockId, BlockTag};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;
use std::sync::Arc;

/// Type alias for starknet-rs Felt.
pub type StarknetRsFelt = starknet_rust::core::types::Felt;
/// Type alias for starknet-types-core Felt.
pub type CoreFelt = starknet_types_core::felt::Felt;

/// Convert from starknet-types-core Felt to starknet-rs Felt.
#[inline]
pub fn core_felt_to_rs(felt: CoreFelt) -> StarknetRsFelt {
    StarknetRsFelt::from_bytes_be(&felt.to_bytes_be())
}

/// Convert from starknet-rs Felt to starknet-types-core Felt.
#[inline]
pub fn rs_felt_to_core(felt: StarknetRsFelt) -> CoreFelt {
    CoreFelt::from_bytes_be(&felt.to_bytes_be())
}

/// Check whether a contract is deployed at the given address.
///
/// Queries `getClassHashAt` — if the call succeeds, the address is deployed.
pub async fn check_deployed(
    provider: &Arc<JsonRpcClient<HttpTransport>>,
    address: StarknetRsFelt,
) -> Result<bool> {
    match provider
        .get_class_hash_at(BlockId::Tag(BlockTag::Latest), address)
        .await
    {
        Ok(_) => Ok(true),
        Err(e) => {
            let msg = e.to_string();
            // "Contract not found", "ContractNotFound", or similar indicates not deployed
            if msg.contains("not found")
                || msg.contains("is not deployed")
                || msg.contains("ContractNotFound")
            {
                Ok(false)
            } else {
                Err(KmsError::RpcError(msg))
            }
        }
    }
}

/// Extract a `u128` from the low 16 bytes of a starknet-rs Felt.
pub(crate) fn felt_to_u128(felt: &StarknetRsFelt) -> u128 {
    let bytes = felt.to_bytes_be();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[16..32]);
    u128::from_be_bytes(buf)
}

/// Extract a `u16` from the low 2 bytes of a starknet-rs Felt.
pub(crate) fn felt_to_u16(felt: &StarknetRsFelt) -> u16 {
    let bytes = felt.to_bytes_be();
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[30..32]);
    u16::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_felt_roundtrip() {
        let core = CoreFelt::from(0xDEADBEEFu64);
        let rs = core_felt_to_rs(core);
        let back = rs_felt_to_core(rs);
        assert_eq!(core, back);
    }

    #[test]
    fn test_felt_zero() {
        let core = CoreFelt::ZERO;
        let rs = core_felt_to_rs(core);
        assert_eq!(rs, StarknetRsFelt::ZERO);
    }
}
