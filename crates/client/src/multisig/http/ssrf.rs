//! SSRF protections for the HTTP coordinator: URL/scheme validation, a
//! public-only DNS resolver, and blocked-range checks for IPv4/IPv6 (including
//! NAT64 and legacy transition embeddings).

use krusty_kms_common::{KmsError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Debug)]
struct SsrfBlockedRedirect(String);

impl std::fmt::Display for SsrfBlockedRedirect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SsrfBlockedRedirect {}

/// DNS resolver that rejects non-public addresses on every lookup.
///
/// Used by the SSRF-safe HTTP client so connection-time resolution cannot
/// rebind to an internal IP after a successful preflight check.
#[derive(Debug, Default)]
struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let raw = name.as_str().trim_end_matches('.');
            // reqwest may pass IPv6 literals with brackets; strip them so we can
            // apply the same IP policy without a spurious DNS lookup.
            let host = raw
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(raw);

            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_blocked_ip(ip) {
                    return Err(Box::new(std::io::Error::other(format!(
                        "coordinator host '{host}' is a blocked IP address"
                    )))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
                let iter: reqwest::dns::Addrs = Box::new(std::iter::once(SocketAddr::new(ip, 0)));
                return Ok(iter);
            }

            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0))
                .await
                .map_err(|error| {
                    Box::new(std::io::Error::other(format!(
                        "DNS resolve failed for '{host}': {error}"
                    ))) as Box<dyn std::error::Error + Send + Sync>
                })?
                .collect();

            if addrs.is_empty() {
                return Err(Box::new(std::io::Error::other(format!(
                    "coordinator host '{host}' resolved to no addresses"
                )))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            // Fail closed if any address is non-public (rebinding / mixed RRset).
            if addrs.iter().any(|addr| is_blocked_ip(addr.ip())) {
                return Err(Box::new(std::io::Error::other(format!(
                    "coordinator host '{host}' resolved to a blocked address"
                )))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            let iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

pub(super) fn build_ssrf_safe_client(
    url: &Url,
    connect_timeout: Duration,
    read_timeout: Duration,
    request_timeout: Duration,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .read_timeout(read_timeout)
        .timeout(request_timeout)
        // Bypass env/system proxies so DNS pinning and PublicOnlyResolver
        // apply to the actual coordinator destination (not a proxy hop).
        .no_proxy()
        .dns_resolver(Arc::new(PublicOnlyResolver))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                return attempt.error(SsrfBlockedRedirect(
                    "too many redirects while contacting coordinator".to_string(),
                ));
            }
            match validate_coordinator_url(attempt.url()) {
                Ok(()) => attempt.follow(),
                Err(error) => attempt.error(SsrfBlockedRedirect(error.to_string())),
            }
        }));

    // Pin the initially validated public addresses for the base host so the
    // first connection cannot race a different A/AAAA set. Redirects to other
    // hosts still go through PublicOnlyResolver.
    if let Some(url::Host::Domain(domain)) = url.host() {
        let port = url.port_or_known_default().unwrap_or(80);
        let addrs = resolve_public_socket_addrs(domain, port)?;
        builder = builder.resolve_to_addrs(domain, &addrs);
    }

    builder
        .build()
        .map_err(|error| KmsError::MultisigError(error.to_string()))
}

fn resolve_public_socket_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|error| {
            KmsError::MultisigError(format!(
                "failed to resolve coordinator host '{host}': {error}"
            ))
        })?
        .collect();

    if addrs.is_empty() {
        return Err(KmsError::MultisigError(format!(
            "coordinator host '{host}' resolved to no addresses"
        )));
    }

    for addr in &addrs {
        if is_blocked_ip(addr.ip()) {
            return Err(KmsError::MultisigError(format!(
                "coordinator host '{host}' resolves to blocked address {}",
                addr.ip()
            )));
        }
    }

    Ok(addrs)
}

pub(super) fn validate_coordinator_url(url: &Url) -> Result<()> {
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(KmsError::MultisigError(format!(
                "unsupported coordinator URL scheme '{other}' (only http/https)"
            )));
        }
    }

    let host = url
        .host()
        .ok_or_else(|| KmsError::MultisigError("coordinator URL missing host".to_string()))?;

    match host {
        url::Host::Ipv4(v4) => {
            if is_blocked_ipv4(v4) {
                return Err(KmsError::MultisigError(format!(
                    "coordinator host '{v4}' is a blocked IP address"
                )));
            }
            Ok(())
        }
        url::Host::Ipv6(v6) => {
            // Prefer `url::Host::Ipv6` over `host_str()`: the latter includes
            // brackets, which break `IpAddr` parsing and skipped IPv6 SSRF checks.
            if is_blocked_ip(IpAddr::V6(v6)) {
                return Err(KmsError::MultisigError(format!(
                    "coordinator host '{v6}' is a blocked IP address"
                )));
            }
            Ok(())
        }
        url::Host::Domain(domain) => {
            let host_lower = domain.to_ascii_lowercase();
            if host_lower == "localhost"
                || host_lower.ends_with(".localhost")
                || host_lower == "metadata.google.internal"
            {
                return Err(KmsError::MultisigError(format!(
                    "coordinator host '{domain}' is blocked (loopback/metadata)"
                )));
            }

            let port = url.port_or_known_default().unwrap_or(80);
            // Hostname: resolve and require every address to be publicly routable.
            let _ = resolve_public_socket_addrs(domain, port)?;
            Ok(())
        }
    }
}

/// Returns true for non-public / special-use addresses (SSRF targets).
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ipv4(v4);
            }
            // NAT64 / IPv4-translation prefixes (RFC 6052 / RFC 8215): reject
            // when the embedded IPv4 destination is itself blocked.
            if let Some(v4) = ipv4_from_nat64_prefix(v6) {
                return is_blocked_ipv4(v4);
            }
            // Local-use NAT64 `64:ff9b:1::/48` with a non-/96 layout we cannot
            // decode — fail closed rather than allow a private embedding.
            if is_local_use_nat64_prefix(v6) {
                return true;
            }
            // Legacy transition formats (6to4, IPv4-compatible) embed an IPv4
            // destination the same way NAT64 does.
            if let Some(v4) = ipv4_from_transition_prefix(v6) {
                return is_blocked_ipv4(v4);
            }
            is_blocked_ipv6(v6)
        }
    }
}

fn is_blocked_ipv4(v4: Ipv4Addr) -> bool {
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.octets()[0] == 0
        // CGNAT 100.64.0.0/10
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
        // AWS/GCP metadata
        || v4.octets() == [169, 254, 169, 254]
        // IETF Protocol Assignments 192.0.0.0/24 (except .9/.10 sometimes)
        || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
        // Benchmarking 198.18.0.0/15
        || (v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19))
        // Reserved / future use 240.0.0.0/4
        || v4.octets()[0] >= 240
}

fn is_blocked_ipv6(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || v6.is_unicast_link_local()
        || v6.is_unique_local()
        // Deprecated site-local fec0::/10 (RFC 3879) — still routed internally
        // on some networks, so treat it like the other private ranges.
        || (v6.segments()[0] & 0xffc0) == 0xfec0
        // Documentation 2001:db8::/32
        || v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8
        // Discard prefix 100::/64
        || (v6.segments()[0] == 0x0100 && v6.segments()[1..4] == [0, 0, 0])
}

fn ipv4_from_u16_pair(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

/// Extract an IPv4 address embedded in a NAT64 translation prefix.
///
/// Handles:
/// - RFC 6052 well-known prefix `64:ff9b::/96` (IPv4 in the last 32 bits)
/// - RFC 8215 local-use prefix `64:ff9b:1::/48` with `/96`-style embedding
///   (e.g. `64:ff9b:1::a00:1` → `10.0.0.1`)
/// - RFC 6052 PLEN=48 embedding under the local-use prefix
fn ipv4_from_nat64_prefix(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();

    // Well-known NAT64 prefix 64:ff9b::/96
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(ipv4_from_u16_pair(s[6], s[7]));
    }

    // Local-use NAT64 64:ff9b:1::/48 with /96-style suffix (Codex example).
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(ipv4_from_u16_pair(s[6], s[7]));
    }

    // RFC 6052 PLEN=48 under local-use: IPv4 in bits 48-63 and 72-87
    // (bits 64-71 are the "u" octet and must be zero).
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 && (s[4] >> 8) == 0 {
        return Some(Ipv4Addr::new(
            (s[3] >> 8) as u8,
            s[3] as u8,
            s[4] as u8,
            (s[5] >> 8) as u8,
        ));
    }

    None
}

fn is_local_use_nat64_prefix(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001
}

/// Extract an IPv4 address embedded in a legacy IPv6 transition format.
///
/// Handles:
/// - 6to4 `2002::/16` (RFC 3056), IPv4 in bits 16-47
/// - deprecated IPv4-compatible `::a.b.c.d` (RFC 4291), IPv4 in the low 32 bits
fn ipv4_from_transition_prefix(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();

    // 6to4 2002::/16 — e.g. `2002:0a00:0001::` → 10.0.0.1
    if s[0] == 0x2002 {
        return Some(ipv4_from_u16_pair(s[1], s[2]));
    }

    // IPv4-compatible ::a.b.c.d — e.g. `::a00:1` → 10.0.0.1
    if s[..6] == [0, 0, 0, 0, 0, 0] && (s[6], s[7]) != (0, 0) {
        return Some(ipv4_from_u16_pair(s[6], s[7]));
    }

    None
}
