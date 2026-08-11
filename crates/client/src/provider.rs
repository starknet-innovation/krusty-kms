//! Starknet RPC provider utilities.

use krusty_kms_common::Result;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use url::Url;

/// Create a Starknet JSON-RPC provider from a URL.
///
/// # Arguments
/// * `rpc_url` - The RPC endpoint URL (e.g., "https://api.cartridge.gg/x/starknet/sepolia")
///
/// # Transport security
///
/// Only `https://` endpoints are accepted, with one exception: plain `http://`
/// is allowed for loopback hosts (`localhost`, `127.0.0.1`, `::1`) so local
/// devnets keep working. Everything this provider reports (nonces, balances,
/// deployment state, contract parameters) feeds signing decisions, so a
/// cleartext remote transport would hand a network attacker that influence.
///
/// # Returns
/// A configured `JsonRpcClient` that can be used to interact with Starknet.
pub fn create_provider(rpc_url: &str) -> Result<JsonRpcClient<HttpTransport>> {
    let url = Url::parse(rpc_url)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid RPC URL: {}", e)))?;

    validate_rpc_url_scheme(&url)?;

    Ok(JsonRpcClient::new(HttpTransport::new(url)))
}

fn validate_rpc_url_scheme(url: &Url) -> Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if host_is_loopback(url) => Ok(()),
        "http" => Err(krusty_kms_common::KmsError::RpcError(format!(
            "plain http:// RPC endpoints are only allowed for loopback hosts, got {url}"
        ))),
        other => Err(krusty_kms_common::KmsError::RpcError(format!(
            "unsupported RPC URL scheme '{other}' (expected https)"
        ))),
    }
}

fn host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_provider() {
        let provider = create_provider("https://api.cartridge.gg/x/starknet/sepolia");
        assert!(provider.is_ok());
    }

    /// Cleartext transports for remote RPC endpoints are rejected (M-14);
    /// loopback devnets remain usable.
    #[test]
    fn test_rejects_cleartext_remote_rpc() {
        assert!(create_provider("http://api.cartridge.gg/x/starknet/sepolia").is_err());
        assert!(create_provider("http://192.168.1.10:5050").is_err());
        assert!(create_provider("ftp://example.com").is_err());
        assert!(create_provider("ws://example.com").is_err());

        assert!(create_provider("http://localhost:5050").is_ok());
        assert!(create_provider("http://127.0.0.1:5050").is_ok());
        assert!(create_provider("http://[::1]:5050").is_ok());
    }
}
