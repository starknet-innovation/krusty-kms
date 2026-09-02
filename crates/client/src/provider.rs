//! Starknet RPC provider utilities.

use krusty_kms_common::error::redact_url;
use krusty_kms_common::Result;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use url::Url;

const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RPC_READ_TIMEOUT: Duration = Duration::from_secs(15);
const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
/// rejected. The HTTP client is then pinned to **every** address in that
/// RRset so `HttpTransport` cannot re-resolve the name (DNS rebinding) and
/// dual-stack loopback listeners still have a fallback. Cleartext clients
/// also disable proxies and redirects so a 307 or `http_proxy` cannot send
/// the JSON-RPC POST off-loopback.
///
/// HTTPS clients also disable ambient proxies and redirects. This keeps RPC
/// request bodies and query metadata bound to the configured origin.
///
/// Everything this provider reports (nonces, balances, deployment state,
/// contract parameters) feeds signing decisions, so a cleartext remote
/// transport would hand a network attacker that influence.
///
/// # Returns
/// A configured `JsonRpcClient` that can be used to interact with Starknet.
pub fn create_provider(rpc_url: &str) -> Result<JsonRpcClient<HttpTransport>> {
    let url = Url::parse(rpc_url)
        .map_err(|e| krusty_kms_common::KmsError::RpcError(format!("Invalid RPC URL: {}", e)))?;

    Ok(JsonRpcClient::new(rpc_http_transport(url)?))
}

fn rpc_http_transport(url: Url) -> Result<HttpTransport> {
    match url.scheme() {
        "https" => Ok(HttpTransport::new_with_client(
            url,
            bounded_rpc_http_client()?,
        )),
        "http" => {
            let client = cleartext_loopback_http_client(&url)?;
            Ok(HttpTransport::new_with_client(url, client))
        }
        other => Err(krusty_kms_common::KmsError::RpcError(format!(
            "unsupported RPC URL scheme '{other}' (expected https)"
        ))),
    }
}

fn rpc_http_client_builder(
    connect_timeout: Duration,
    read_timeout: Duration,
    request_timeout: Duration,
) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .read_timeout(read_timeout)
        .timeout(request_timeout)
}

fn bounded_rpc_http_client() -> Result<reqwest::Client> {
    rpc_http_client_builder(RPC_CONNECT_TIMEOUT, RPC_READ_TIMEOUT, RPC_REQUEST_TIMEOUT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| {
            krusty_kms_common::KmsError::RpcError(format!(
                "failed to build RPC HTTP client: {error}"
            ))
        })
}

/// Build a cleartext HTTP client that can only reach loopback.
///
/// Loopback IP literals need no DNS pin. For `localhost`, resolve now, require
/// every answer to be loopback, and pin **all** of those addresses so later
/// requests neither rebind nor drop a dual-stack fallback.
fn cleartext_loopback_http_client(url: &Url) -> Result<reqwest::Client> {
    let mut builder =
        rpc_http_client_builder(RPC_CONNECT_TIMEOUT, RPC_READ_TIMEOUT, RPC_REQUEST_TIMEOUT)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
    if let Some((host, addrs)) = localhost_loopback_pin(url)? {
        builder = builder.resolve_to_addrs(&host, &addrs);
    }
    builder.build().map_err(|error| {
        krusty_kms_common::KmsError::RpcError(format!(
            "failed to build cleartext RPC HTTP client: {error}"
        ))
    })
}

/// `Some((host, addrs))` when the URL uses `localhost` and every resolved
/// address is loopback. `None` for loopback IP literals.
fn localhost_loopback_pin(url: &Url) -> Result<Option<(String, Vec<SocketAddr>)>> {
    pin_localhost(url, resolve_host)
}

fn pin_localhost(
    url: &Url,
    resolve: impl Fn(&str, u16) -> Result<Vec<SocketAddr>>,
) -> Result<Option<(String, Vec<SocketAddr>)>> {
    match url.host() {
        Some(url::Host::Ipv4(v4)) if v4.is_loopback() => Ok(None),
        Some(url::Host::Ipv6(v6)) if ip_is_cleartext_loopback(IpAddr::V6(v6)) => Ok(None),
        Some(url::Host::Domain(domain)) if domain.eq_ignore_ascii_case("localhost") => {
            // `http` always has a known default; fail closed rather than invent a port.
            // Error text carries only `scheme://host[:port]`: the path and
            // query of an RPC URL usually hold the provider API key.
            let port = url.port_or_known_default().ok_or_else(|| {
                krusty_kms_common::KmsError::RpcError(format!(
                    "plain http:// RPC URL is missing a port, got {}",
                    redact_url(url.as_str())
                ))
            })?;
            let addrs = resolve(domain, port)?;
            require_loopback_addrs(domain, &addrs)?;
            Ok(Some((domain.to_string(), addrs)))
        }
        Some(_) => Err(krusty_kms_common::KmsError::RpcError(format!(
            "plain http:// RPC endpoints are only allowed for loopback hosts, got {}",
            redact_url(url.as_str())
        ))),
        None => Err(krusty_kms_common::KmsError::RpcError(format!(
            "plain http:// RPC endpoint is missing a host, got {}",
            redact_url(url.as_str())
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
    use tokio::time::Instant;

    #[test]
    fn test_create_provider() {
        let provider = create_provider("https://api.cartridge.gg/x/starknet/sepolia");
        assert!(provider.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn rpc_client_timeout_bounds_a_stalled_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _connection = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        let timeout = Duration::from_millis(50);
        let client = rpc_http_client_builder(timeout, timeout, timeout)
            .no_proxy()
            .build()
            .unwrap();
        let started = Instant::now();
        let error = client
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap_err();

        assert!(error.is_timeout());
        assert_eq!(started.elapsed(), timeout);
        server.abort();
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

    /// Rejection messages name only `scheme://host[:port]` (M-2): the path
    /// and query of an RPC URL usually carry the provider API key.
    #[test]
    fn cleartext_rejection_message_redacts_path_and_query() {
        let error = create_provider("http://10.0.0.1:5050/v0_9/SECRET_TOKEN?apikey=SECRET_TOKEN")
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("http://10.0.0.1:5050"), "{message}");
        assert!(!message.contains("SECRET_TOKEN"), "{message}");
        assert!(!message.contains("v0_9"), "{message}");
    }

    #[test]
    fn malformed_rpc_url_is_rpc_error() {
        match create_provider("not a url") {
            Err(krusty_kms_common::KmsError::RpcError(message)) => {
                assert!(message.contains("Invalid RPC URL"));
            }
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    #[test]
    fn localhost_http_pins_every_validated_loopback_addr() {
        let url = Url::parse("http://localhost:5050").unwrap();
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5050);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5050);
        let (host, addrs) = pin_localhost(&url, |_, _| Ok(vec![v6, v4]))
            .unwrap()
            .expect("localhost must pin DNS");
        assert!(host.eq_ignore_ascii_case("localhost"));
        assert_eq!(addrs, vec![v6, v4]);

        assert!(
            pin_localhost(&Url::parse("http://127.0.0.1:5050").unwrap(), |_, _| Ok(
                vec![]
            ))
            .unwrap()
            .is_none()
        );
        assert!(
            pin_localhost(&Url::parse("http://[::1]:5050").unwrap(), |_, _| Ok(vec![]))
                .unwrap()
                .is_none()
        );
        assert!(
            pin_localhost(&Url::parse("http://example.com").unwrap(), |_, _| Ok(vec![
                v4
            ]))
            .is_err()
        );
    }

    #[test]
    fn pin_localhost_rejects_synthetic_mixed_rrset() {
        let url = Url::parse("http://localhost:5050/rpc/v0_7?x=1").unwrap();
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5050);
        let metadata = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80);
        assert!(pin_localhost(&url, |_, _| Ok(vec![loopback, metadata])).is_err());
        assert!(pin_localhost(&url, |_, _| Ok(vec![])).is_err());
        let (host, addrs) = pin_localhost(&url, |_, _| Ok(vec![loopback]))
            .unwrap()
            .expect("loopback-only RRset must pin");
        assert_eq!(host, "localhost");
        assert_eq!(addrs, vec![loopback]);
        assert_eq!(url.path(), "/rpc/v0_7");
        assert_eq!(url.query(), Some("x=1"));
    }

    #[test]
    fn dual_stack_loopback_pin_keeps_ipv4_and_ipv6() {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5050);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5050);
        let addrs = [v6, v4];
        require_loopback_addrs("localhost", &addrs).unwrap();
        assert!(addrs.iter().all(|addr| ip_is_cleartext_loopback(addr.ip())));
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
