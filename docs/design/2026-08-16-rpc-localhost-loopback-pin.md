# Design: pin cleartext localhost RPC to loopback

Date: 2026-08-16

## Problem

`create_provider` allowed `http://localhost` by host string. A poisoned
resolver that maps that name to metadata or RFC1918 still produced a
cleartext client, and RPC responses feed signing decisions. Construction-time
DNS alone is also TOCTOU: `HttpTransport` re-resolves the hostname later.

## Interface

`create_provider` is unchanged. For `http://localhost` it now:

1. Resolves the name and fail-closes unless every address is loopback.
2. Builds `HttpTransport` with a reqwest 0.13 client whose `resolve_to_addrs`
   map retains **every** validated address (IPv4 and IPv6), so later requests
   do not ask DNS again and dual-stack listeners still have a fallback.

Loopback IP literals skip DNS pinning. HTTPS is unchanged.

## Dependency

`krusty-kms-client` moves from reqwest 0.12 to 0.13 so the client type
matches `HttpTransport::new_with_client` (already on 0.13 via
`starknet-rust`). TLS feature name is `rustls` (0.13 dropped `rustls-tls`).
The HTTP coordinator SSRF client uses the same crate.

## Invariants

- Cleartext HTTP is only for loopback destinations.
- `localhost` connections use the construction-time loopback RRset in full.
- Mixed RRsets (loopback + RFC1918/metadata) are rejected.

## Failure modes

DNS failure, an empty RRset, or any non-loopback answer returns
`KmsError::RpcError`. IPv6-only local servers remain reachable when `::1` is
in that RRset.
