//! Starknet RPC provider utilities.

use krusty_kms_common::Result;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use url::Url;

/// Create a Starknet JSON-RPC provider from a URL.
///
/// # Arguments
/// * `rpc_url` - The RPC endpoint URL (e.g., "https://api.cartridge.gg/x/starknet/sepolia")
///
/// # Transport security
///
/// Only `https://` endpoints are accepted, with one exception: plain `http://`
/// is allowed for loopback destinations so local devnets keep working.
///
/// For IP literals the address itself must be loopback (`127.0.0.0/8` or
/// `::1`, including IPv4-mapped `::ffff:127.0.0.1`). For the `localhost`
/// hostname, every DNS answer is required to be loopback — a poisoned
/// `/etc/hosts` or resolver that maps `localhost` to metadata/RFC1918 is
/// rejected. The HTTP client is then pinned to that RRset so a later lookup
/// inside `HttpTransport` cannot rebind to a non-loopback address.
///
/// Everything this provider reports (nonces, balances, deployment state,
/// contract parameters) feeds signing decisions, so a cleartext remote
/// transport would hand a network attacker that influence.
///
/// # Returns
/// A configured `JsonRpcClient` that can be used to interact with Starknet.
pub fn create_provider(rpc_url: &str) -> Result<JsonRpcClient<HttpTransport>> {
    let url = Url::parse(rpc_url)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid RPC URL: {}", e)))?;

    Ok(JsonRpcClient::new(rpc_http_transport(url)?))
}

fn rpc_http_transport(url: Url) -> Result<HttpTransport> {
    match url.scheme() {
        "https" => Ok(HttpTransport::new(url)),
        "http" => {
            let client = cleartext_loopback_http_client(&url)?;
            Ok(HttpTransport::new_with_client(url, client))
        }
        other => Err(krusty_kms_common::KmsError::RpcError(format!(
            "unsupported RPC URL scheme '{other}' (expected https)"
        ))),
    }
}

/// Build a cleartext HTTP client that can only reach loopback.
///
/// Loopback IP literals need no DNS pin. For `localhost`, resolve now, require
/// every answer to be loopback, and `resolve_to_addrs` so subsequent requests
/// reuse that RRset instead of asking the resolver again (DNS rebinding).
fn cleartext_loopback_http_client(url: &Url) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().no_proxy();
    if let Some((host, addrs)) = loopback_dns_override(url)? {
        builder = builder.resolve_to_addrs(&host, &addrs);
    }
    builder.build().map_err(|error| {
        krusty_kms_common::KmsError::RpcError(format!(
            "failed to build cleartext RPC HTTP client: {error}"
        ))
    })
}

/// `Some((host, addrs))` when the URL uses the `localhost` name and every
/// resolved address is loopback. `None` for loopback IP literals.
fn loopback_dns_override(url: &Url) -> Result<Option<(String, Vec<SocketAddr>)>> {
    match url.host() {
        Some(url::Host::Ipv4(v4)) if v4.is_loopback() => Ok(None),
        Some(url::Host::Ipv6(v6)) if ip_is_cleartext_loopback(IpAddr::V6(v6)) => Ok(None),
        Some(url::Host::Domain(domain)) if domain.eq_ignore_ascii_case("localhost") => {
            let port = url.port_or_known_default().unwrap_or(80);
            let addrs = resolve_host(domain, port)?;
            require_loopback_addrs(domain, &addrs)?;
            Ok(Some((domain.to_string(), addrs)))
        }
        Some(_) => Err(krusty_kms_common::KmsError::RpcError(format!(
            "plain http:// RPC endpoints are only allowed for loopback hosts, got {url}"
        ))),
        None => Err(krusty_kms_common::KmsError::RpcError(format!(
            "plain http:// RPC endpoint is missing a host, got {url}"
        ))),
    }
}

fn resolve_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    (host, port)
        .to_socket_addrs()
        .map(Iterator::collect)
        .map_err(|error| {
            krusty_kms_common::KmsError::RpcError(format!(
                "failed to resolve cleartext RPC host '{host}': {error}"
            ))
        })
}

/// True for IPv4 loopback and IPv6 loopback, including IPv4-mapped `::ffff:127.x`.
fn ip_is_cleartext_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn require_loopback_addrs(host: &str, addrs: &[SocketAddr]) -> Result<()> {
    if addrs.is_empty() {
        return Err(krusty_kms_common::KmsError::RpcError(format!(
            "cleartext RPC host '{host}' resolved to no addresses"
        )));
    }
    for addr in addrs {
        if !ip_is_cleartext_loopback(addr.ip()) {
            return Err(krusty_kms_common::KmsError::RpcError(format!(
                "plain http:// RPC host '{host}' resolved to non-loopback address {}",
                addr.ip()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
        assert!(create_provider("http://169.254.169.254/").is_err());
        assert!(create_provider("ftp://example.com").is_err());
        assert!(create_provider("ws://example.com").is_err());

        assert!(create_provider("http://localhost:5050").is_ok());
        assert!(create_provider("http://127.0.0.1:5050").is_ok());
        assert!(create_provider("http://[::1]:5050").is_ok());
        assert!(create_provider("http://[::ffff:127.0.0.1]:5050").is_ok());
        assert!(create_provider("http://[::ffff:169.254.169.254]:5050").is_err());
    }

    #[test]
    fn localhost_http_pins_resolved_loopback_addrs() {
        let url = Url::parse("http://localhost:5050").unwrap();
        let (host, addrs) = loopback_dns_override(&url)
            .unwrap()
            .expect("localhost must pin DNS");
        assert!(host.eq_ignore_ascii_case("localhost"));
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|addr| ip_is_cleartext_loopback(addr.ip())));

        assert!(
            loopback_dns_override(&Url::parse("http://127.0.0.1:5050").unwrap())
                .unwrap()
                .is_none()
        );
        assert!(
            loopback_dns_override(&Url::parse("http://[::1]:5050").unwrap())
                .unwrap()
                .is_none()
        );
        assert!(loopback_dns_override(&Url::parse("http://example.com").unwrap()).is_err());
    }

    #[test]
    fn require_loopback_addrs_rejects_metadata_or_mixed_rrset() {
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5050);
        let metadata = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80);
        let rfc1918 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80);

        assert!(require_loopback_addrs("localhost", &[loopback]).is_ok());
        assert!(require_loopback_addrs("localhost", &[metadata]).is_err());
        assert!(require_loopback_addrs("localhost", &[loopback, rfc1918]).is_err());
        assert!(require_loopback_addrs("localhost", &[]).is_err());
    }

    #[test]
    fn ipv4_mapped_loopback_is_accepted_mapped_metadata_is_not() {
        assert!(ip_is_cleartext_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(ip_is_cleartext_loopback(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(ip_is_cleartext_loopback(
            "::ffff:127.0.0.1".parse().unwrap()
        ));
        assert!(!ip_is_cleartext_loopback(
            "::ffff:169.254.169.254".parse().unwrap()
        ));
        assert!(!ip_is_cleartext_loopback(
            "::ffff:10.0.0.1".parse().unwrap()
        ));
    }
}
