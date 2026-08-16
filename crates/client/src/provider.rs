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
/// rejected. The URL is then rewritten to a validated loopback IP literal
/// so `HttpTransport` never re-resolves the `localhost` name (DNS rebinding).
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

    Ok(JsonRpcClient::new(HttpTransport::new(pin_rpc_url(url)?)))
}

fn pin_rpc_url(url: Url) -> Result<Url> {
    match url.scheme() {
        "https" => Ok(url),
        "http" => pin_cleartext_loopback_url(url),
        other => Err(krusty_kms_common::KmsError::RpcError(format!(
            "unsupported RPC URL scheme '{other}' (expected https)"
        ))),
    }
}

/// Accept only loopback cleartext destinations, and rewrite `localhost` to a
/// validated loopback IP so later HTTP requests cannot rebind via DNS.
fn pin_cleartext_loopback_url(mut url: Url) -> Result<Url> {
    match url.host() {
        Some(url::Host::Ipv4(v4)) if v4.is_loopback() => Ok(url),
        Some(url::Host::Ipv6(v6)) if ip_is_cleartext_loopback(IpAddr::V6(v6)) => Ok(url),
        Some(url::Host::Domain(domain)) if domain.eq_ignore_ascii_case("localhost") => {
            let port = url.port_or_known_default().unwrap_or(80);
            let addrs = resolve_host(domain, port)?;
            require_loopback_addrs(domain, &addrs)?;
            let ip = pick_loopback_ip(&addrs).ok_or_else(|| {
                krusty_kms_common::KmsError::RpcError(format!(
                    "cleartext RPC host '{domain}' resolved to no addresses"
                ))
            })?;
            url.set_ip_host(ip).map_err(|()| {
                krusty_kms_common::KmsError::RpcError(format!(
                    "failed to pin cleartext RPC URL {url} to loopback address {ip}"
                ))
            })?;
            Ok(url)
        }
        Some(_) => Err(krusty_kms_common::KmsError::RpcError(format!(
            "plain http:// RPC endpoints are only allowed for loopback hosts, got {url}"
        ))),
        None => Err(krusty_kms_common::KmsError::RpcError(format!(
            "plain http:// RPC endpoint is missing a host, got {url}"
        ))),
    }
}

/// Prefer IPv4 loopback when present so IPv4-only local listeners keep working.
fn pick_loopback_ip(addrs: &[SocketAddr]) -> Option<IpAddr> {
    addrs
        .iter()
        .map(SocketAddr::ip)
        .find(|ip| matches!(ip, IpAddr::V4(_)))
        .or_else(|| addrs.first().map(SocketAddr::ip))
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
    fn localhost_http_is_rewritten_to_a_loopback_ip_literal() {
        let url = pin_cleartext_loopback_url(Url::parse("http://localhost:5050").unwrap()).unwrap();
        match url.host() {
            Some(url::Host::Ipv4(v4)) => assert!(v4.is_loopback()),
            Some(url::Host::Ipv6(v6)) => {
                assert!(ip_is_cleartext_loopback(IpAddr::V6(v6)));
            }
            other => panic!("expected loopback IP literal, got {other:?}"),
        }
        assert_eq!(url.port(), Some(5050));

        let v4 = pin_cleartext_loopback_url(Url::parse("http://127.0.0.1:5050").unwrap()).unwrap();
        assert!(matches!(v4.host(), Some(url::Host::Ipv4(_))));
        let v6 = pin_cleartext_loopback_url(Url::parse("http://[::1]:5050").unwrap()).unwrap();
        assert!(matches!(v6.host(), Some(url::Host::Ipv6(_))));
        assert!(pin_cleartext_loopback_url(Url::parse("http://example.com").unwrap()).is_err());
    }

    #[test]
    fn pick_loopback_ip_prefers_ipv4() {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5050);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5050);
        assert_eq!(
            pick_loopback_ip(&[v6, v4]),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            pick_loopback_ip(&[v6]),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(pick_loopback_ip(&[]), None);
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
