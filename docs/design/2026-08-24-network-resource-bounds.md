# Network resource budgets

## Context

Starknet RPC and multisig coordinator endpoints are untrusted inputs. The
default asynchronous HTTP clients had no total request timeout, transaction
acceptance deadlines were checked only between RPC awaits, coordinator JSON
was collected without a byte/count limit, and event pagination trusted the RPC
to eventually terminate.

## Decision

Apply fixed conservative defaults at each network layer:

- RPC and SSRF-safe coordinator clients use 10-second connect, 15-second
  read-idle, and 30-second total request timeouts.
- HTTPS RPC clients reject redirects and ignore ambient proxy variables so
  request bodies stay on the configured origin.
- Transaction acceptance wraps each in-flight observation in the caller's
  remaining deadline.
- HTTP coordinator responses are streamed into a 1 MiB buffer and contain at
  most 1,024 envelopes during direct typed decoding and signature validation.
- A Tongo event query has a 60-second aggregate deadline and permits at most
  1,000 pages, 100,000 decoded events, and 32 MiB of serialized event data.
  Continuation tokens must not repeat or exceed 4 KiB.

Pagination policy and its regression tests live in a dedicated module so the
event parser remains reviewable and stays below its file-size ratchet.

## Failure behavior

Budget exhaustion fails closed through existing `RpcError`, `Timeout`, or
`MultisigError` variants. No partial event/envelope result is returned. The
explicit unchecked coordinator constructor continues to bypass SSRF host
validation for trusted local tooling, but its client is built with the same
request deadlines and response limits as the checked path.

## Known residual

`starknet-rust` 0.19.1's public `HttpTransport` calls `response.text()` before
deserialization and exposes no response-body hook. Replacing it with a local
bounded transport changes the concrete provider type in multiple published
constructors and fails the repository's semver gate. This PR therefore keeps
the compatible type: the 30-second request deadline bounds transfer time, and
the event byte budget bounds retained decoded data, but a fast chunked RPC
response can still cause a transient allocation before those checks run. A
future `starknet-rust` transport limit or a versioned public API migration is
required to remove that residual safely.
