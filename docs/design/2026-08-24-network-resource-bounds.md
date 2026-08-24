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
- Transaction acceptance wraps each in-flight observation in the caller's
  remaining deadline.
- HTTP coordinator responses are streamed into a 1 MiB buffer and contain at
  most 1,024 envelopes before typed decoding and signature validation.
- A Tongo event query permits at most 1,000 pages and 100,000 decoded events;
  continuation tokens must not repeat.

Pagination policy and its regression tests live in a dedicated module so the
event parser remains reviewable and stays below its file-size ratchet.

## Failure behavior

Budget exhaustion fails closed through existing `RpcError`, `Timeout`, or
`MultisigError` variants. No partial event/envelope result is returned. The
explicit unchecked coordinator constructor continues to bypass SSRF host
validation for trusted local tooling, but request deadlines and response limits
still apply to its publish/read operations.
