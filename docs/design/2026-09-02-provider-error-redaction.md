# Signing-key lifetime and endpoint-safe provider errors

Date: 2026-09-02. Status: accepted. Origin: security audit findings M-1, M-2.

## Problems

1. The gateway copied the private key into a starknet-rs `SigningKey`
   (`#[derive(Debug, Clone)]` over a plain `Felt`, no `Zeroize`/`Drop`) and kept
   it alive, inside `LocalWallet` and `OpenZeppelinAccountFactory`, across the
   deploy acceptance wait (up to 15 minutes). Public-key derivation and
   descriptor validation built further throwaway copies.
2. starknet-rs-providers wraps `reqwest::Error` transparently and its `Display`
   appends `for url (<full url>)`. Every `ProviderError::to_string()` site
   copied the RPC URL, whose path or query commonly carries the provider API
   key, into `GatewayError.message` (oracle responses, the 24-hour operation
   store) and `KmsError::RpcError`.

## Decisions

**Lifetime invariant.** starknet-rs `SigningKey` is a non-zeroizing copy of the
secret scalar. In the gateway it may exist only inside
`StarknetGatewayBackend::submit_open_zeppelin_deploy`, which returns the
transaction hash; the acceptance wait starts after that function returns.
Every other consumer (public-key derivation, descriptor validation) reads the
`SecretFelt` in place through `krusty_kms::stark_public_key`.

**Redaction contract.** `krusty_kms_common::error::redact_url(&str) -> String`
returns `scheme://host[:port]`, dropping userinfo, path, query and fragment;
input without a `scheme://host` prefix returns `REDACTED_URL_PLACEHOLDER`,
never the input. Hand-rolled so `common` gains no dependency.

**Provider errors** are described by one helper per crate
(`gateway::backend::rpc::provider_error_message`,
`client::wallet::utils::provider_error_message`; the dependency layering
forbids sharing starknet-rs-typed logic through `common`). Typed
`StarknetError` / `RateLimited` / `ArrayLengthMismatch` keep their upstream
text. `ProviderError::Other` is downcast to
`JsonRpcClientError<HttpTransportError>` and mapped to
`provider transport error: <kind>` with kind in
`timeout | connect | status <code> | decode | json-rpc code <n> | other`. No
`Display` text from a transport error is ever embedded.

## Laws (tested)

1. `redact_url` output never contains userinfo, path, query or fragment of its
   input; unparseable input yields the placeholder.
2. For any `ProviderError::Other` whose `Display` contains a URL and token, the
   mapped message contains neither.
3. `derive_account`'s public key equals the starknet-rs `SigningKey`
   derivation it replaced; a zero key errors instead of panicking.
4. Deploy in `SubmitOnly` mode still returns the transaction hash.

## Alternatives considered

- Wrapping `SigningKey` in `Zeroizing`: impossible, the type does not implement
  `Zeroize`; an upstream request is the long-term fix.
- Stripping only the query string: paths also carry keys on common providers.
- Sharing the classifier through `common`: would pull starknet-rs into the
  base crate, violating the dependency layering.

## Guardrail baseline

`crates/client/src/wallet/utils.rs` grows to 368 lines with the classifier and
its tests and is added to the file-size baseline. Moving the tests to a
sibling file was tried and rejected: `cargo llvm-cov` counts inline test code
toward the `crates/client/src/wallet` coverage floor but not a separate
`tests.rs`, so the move dropped the measured floor from 31.8% to 20.9% with no
change in production coverage. Splitting production code instead would exceed
the 10-file PR limit. Follow-up: make the floor measure production lines only.
