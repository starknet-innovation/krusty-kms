# Bounded JSON-RPC transport (audit M-2)

Date: 2026-11-05. Status: accepted. Origin: the 2026-11-04 security audit,
finding M-2, deferred in `2026-11-04-audit-medium-input-bounds.md` and again
in the 0.16.0 release so that it lands before 1.0.0.

## Problem

`starknet-rust-providers`' `HttpTransport` reads every response with
`reqwest::Response::text()`, which buffers the whole body. `reqwest` 0.13 has
no body-size setting, and its connector hook cannot wrap the connection. The
10 s connect, 15 s read and 30 s total timeouts in `create_provider` limit a
download by time only. An RPC endpoint that is hostile, compromised or
reached through a hostile network path can stream hundreds of megabytes
within those limits and exhaust a wallet's or gateway's memory.

## Decision

`krusty-kms-wallet-api` gains `BoundedHttpTransport`, a `JsonRpcTransport`
that sends the same requests as `HttpTransport` and parses the same way. It
differs in four ways:

- It refuses a response whose `Content-Length` exceeds the cap before reading
  it. It streams other bodies chunk by chunk and stops as soon as the total
  would exceed the cap (`ResponseTooLarge { limit }`). The up-front
  allocation is at most 64 KiB, whatever length the server claims.
- The default cap is 16 MiB (`DEFAULT_MAX_RPC_RESPONSE_BYTES`). The SDK's own
  calls (contract `call`s, receipts, nonces, event pages, blocks with
  transaction hashes) are well under 1 MiB. Callers that fetch full blocks or
  contract classes can raise the cap with `with_max_response_bytes`.
- It does not log request or response bodies. `HttpTransport` traces both.
- A batch response id that does not fit `usize` is reported as an unexpected
  id instead of being truncated by an `as` cast.

`StarknetRpcClient = JsonRpcClient<BoundedHttpTransport>` names the provider
type. `create_provider` builds it with the same hardened `reqwest::Client`
(timeouts, no proxies, no redirects, loopback pinning for `http://`).

### Where it lives

The transport lives in `wallet-api` because that is the lowest crate whose
public API (`Tx`) already names the provider type, and the endpoint-safe
classifier `provider_error_message` that must understand the new error type
lives there too. `krusty-kms-gateway` now depends on `krusty-kms-wallet-api`.
This is a new edge in `check-dependency-layers.sh`. It cannot form a cycle,
since wallet-api depends only on common. Gateway drops its copy of the
classifier and uses the shared one, so the two cannot drift.

`wallet-api` gains production dependencies on `reqwest` (already in the
lockfile through `krusty-kms-client` and `starknet-rust-providers`, same
version and features), `serde`, `serde_json`, `thiserror` and `url`. Nothing
new enters `Cargo.lock`.

## Contract

**Breaking Rust API.** Every public type, field, constructor and parameter
that named `JsonRpcClient<HttpTransport>` now names `StarknetRpcClient`: `Tx`,
`create_provider`, `Wallet`, `TongoContract`, `Erc20`, `Staking`,
`TongoEventReader`, `Multisig`, `Account`, the deployment helpers and
`StarknetGatewayBackend`. A caller that built its own
`JsonRpcClient::new(HttpTransport::new(url))` switches to
`BoundedHttpTransport::new(url)`. `krusty-kms-client` re-exports the new
types, so client users need no new dependency.

Error text: a refused body is described as
`provider transport error: response exceeds <limit> bytes`. Other transport
failure kinds are unchanged, and none of them include the endpoint URL.

No WASM, C ABI or FFI wrapper surface changes, since none of them build RPC
providers. The workspace-excluded `krusty-kms-controller` still names
`JsonRpcClient<HttpTransport>`. Its lockfile does not resolve today, and it
is left for a separate change.

## Alternatives rejected

- A generic `T: JsonRpcTransport` parameter on every client type: a larger
  breaking change, and every downstream signature would carry the parameter.
- Wrapping `reqwest` so `HttpTransport` stays: not possible with reqwest
  0.13's public API.
- Waiting for an upstream body cap in `starknet-rust-providers`: there is no
  release that has one, and the audit finding stays open meanwhile.

## Verification

New tests in `wallet-api/src/rpc_transport/tests.rs` use a local HTTP server.
They cover:

- a body exactly at the cap, sent with `Content-Length` and chunked, is
  parsed;
- an over-cap `Content-Length` is refused;
- a chunked over-cap body with no `Content-Length` is refused while
  streaming;
- the error message names the limit and not the endpoint;
- batch reordering, and refusal of unknown, null and whole-batch-error
  responses.

`bash tools/check.sh rust` and the guardrail scripts pass.
