# Pin the V3 tip on every signed transaction

## Problem

`ResourceBoundsCeiling` (2026-09-01) pins the six gas bounds but never set the
V3 `tip`. In `starknet-rs` 0.19 and 0.20, `ExecutionV3::prepare` and
`AccountDeploymentV3::prepare` resolve an unset tip by fetching the pending
block from the provider and taking `median_tip()`, then sign it. Under the
Starknet v0.14 fee model the sequencer collects base fee plus tip for every
unit of L2 gas actually used, so the tip is an amount paid, not a cap. A
hostile or compromised RPC therefore chose an unbounded `u64` fee term on every
invoke and deploy, with or without a ceiling (October 2026 audit, H-1).

## Contract

- `ResourceBoundsCeiling` gains `max_tip: u64` (`#[serde(default)]`), set by
  `with_max_tip`. `new` keeps its signature and sets it to
  `fee::DEFAULT_TIP` (zero). Zero is a valid bid, so `validate` does not
  reject it.
- `krusty-kms-client`: `Wallet::execute` and
  `deploy_oz_account[_with_fee_ceiling]` pin the tip before any estimate or
  send through `fee::pin_execution_tip` / `fee::pin_deployment_tip`;
  `bound_execution` / `bound_deployment` also set it, so a bound builder is
  fully pinned on its own.
- `krusty-kms-gateway`: `submit_open_zeppelin_deploy` pins through
  `deploy::pin_deployment_tip`; `deploy::bound_deployment` also sets it.
- Every existing public signature is unchanged. `ResourceBoundsCeiling` is
  `#[non_exhaustive]`, so the new field is not a construction break.

## Laws

1. The signed tip is exactly `ceiling.max_tip` when a ceiling is configured and
   exactly `DEFAULT_TIP` otherwise. No code path leaves it for `starknet-rs`
   to resolve.
2. Because of 1, `send` performs no `get_block_with_txs` call for tip
   estimation. The only RPC inputs to a signature are the nonce and, when a
   ceiling admits it, the scaled gas estimate.
3. The worst-case fee a ceiling permits is
   `Σ max_amount × max_price_per_unit + l2_gas.max_amount × max_tip`.
4. Serialized ceilings written before `max_tip` existed deserialize with a
   zero tip, never with an RPC-chosen one.

## Behaviour change

Transactions signed without a ceiling previously bid the network's median tip
and now bid zero. Under congestion that can lower inclusion priority; callers
who want a priority fee configure a ceiling with `with_max_tip`. Trading
priority for a bounded fee is the right default for a signer whose RPC is
untrusted.

## Testing

`crates/common/src/fee/tests.rs`: `with_max_tip` round-trips through serde,
`new` defaults to zero, zero is valid, and a ceiling JSON without `max_tip`
deserializes to zero. `crates/client/src/wallet/fee/tests.rs` and
`crates/gateway/src/backend/tests/fee_ceiling.rs`: `prepared()` is synchronous
and fails while the tip is unset, and the test provider sits on an unreachable
port, so a request that prepares proves the tip was pinned locally and no
block was fetched. Tests cover both the no-ceiling pin (tip equals
`DEFAULT_TIP`) and the ceiling pin (tip equals `max_tip`) for invoke and
deploy, and the bound helpers assert the tip beside the six bounds.
