//! Starknet RPC provider utilities.

use krusty_kms_common::Result;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use url::Url;

/// Create a Starknet JSON-RPC provider from a URL.
///
/// # Arguments
/// * `rpc_url` - The RPC endpoint URL (e.g., "https://api.cartridge.gg/x/starknet/sepolia")
///
/// # Returns
/// A configured `JsonRpcClient` that can be used to interact with Starknet.
pub fn create_provider(rpc_url: &str) -> Result<JsonRpcClient<HttpTransport>> {
    let url = Url::parse(rpc_url)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid RPC URL: {}", e)))?;

    Ok(JsonRpcClient::new(HttpTransport::new(url)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_provider() {
        let provider = create_provider("https://api.cartridge.gg/x/starknet/sepolia");
        assert!(provider.is_ok());
    }
}
