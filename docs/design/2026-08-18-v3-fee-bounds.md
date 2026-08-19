# Design: bound V3 transaction fees against a hostile RPC endpoint

Date: 2026-08-18

## Problem

V3 transactions commit `tip` and all six gas amount/price bounds in the
signature. Every submit path left all of them unset, so starknet-rs filled them
from RPC responses: gas from `starknet_estimateFee`, and `tip` from
`median_tip()` of a block body the endpoint itself serves. Nothing validated
that block.

The charged fee is `(l2_gas_price + tip) * l2_gas_consumed + ...`, so the tip is
a per-L2-gas-unit surcharge, not a flat priority bid. An endpoint that runs the
estimate knows `l2_gas_consumed`, so it can pick `tip ~ (balance - base_fee) /
l2_gas_consumed` and take the balance. No collusion with a sequencer is needed,
and a large tip also buys inclusion priority under v0.14 mempool ordering.

Callers could not defend themselves: `Wallet.account` is private with no
accessor, no submit path took a bounds parameter, and `estimate_fee` was a
separate round trip whose result could not be fed back into `execute`.

The three in-scope submission paths now prepare and hash locally:
`Wallet::execute`, `deploy_oz_account`, and the gateway's
`deploy_open_zeppelin`.

## Interface

`krusty_kms_common::fee::FeeBounds` records what a caller has approved. All
three direct paths resolve through it; no existing function signature changed.

```rust
// Supplied by the host's policy or confirmation UI after it shows the
// `fee approval required` amount from an earlier attempt.
let user_approved_fri = approved_fee_from_host;
let wallet = Wallet::from_signing_key(..)?
    .with_fee_bounds(FeeBounds::default().with_max_fee_fri(user_approved_fri));
```

Also `deploy_oz_account_with_bounds` and
`StarknetGatewayBackend::with_fee_bounds`. `FeeBounds::default()` pins the tip
to 0 but approves no fee. It obtains and scales the estimate, then returns a
non-retryable `fee approval required` error containing the resolved maximum
in exact FRI and formatted STRK without signing. A UI or CLI displays that
amount, asks the user, and resubmits with `with_max_fee_fri`. A caller with an
existing policy limit can supply it on the first attempt. The library itself
never invents a threshold or owns a prompt.

Two resolution modes, both funnelling through one approval check:

- `explicit()` — `Some` only when all six gas fields are set, in which case no
  estimate is requested and the endpoint contributes no fee field to the
  signature. The nonce still comes from the endpoint.
- `resolve(&estimate)` — explicit fields win; the rest are the estimate scaled
  by the multipliers (1.5, matching prior starknet-rs behaviour).

`FeeEstimateInput` is six plain scalars rather than `starknet_rust::FeeEstimate`,
which keeps `krusty-kms-common` free of a Starknet dependency and the resolution
logic pure. Each of `client` and `gateway` maps its own estimate into it, and the
builder-setter chain plus `estimate_input`/`resolve_bounds` are duplicated
across the three sites, and that is intentional.

The security-critical part is not duplicated. The resolution order — scale by
the multipliers, then check the approval — lives once, in `FeeBounds::resolve`
and `finish`. Each `resolve_bounds` only picks estimate-vs-explicit, calls
`estimate_fee` on its own builder type, and maps the error. Those mappers are
the reason the helpers cannot merge: the client yields `KmsError` and the
gateway `GatewayError` via `map_deploy_submission_error`, which supplies typed
`InsufficientFeeBalance` / `AlreadyDeployed` classification that a shared helper
would flatten.

`krusty-kms-wallet-api` could host the mechanical parts — it already depends on
`krusty-kms-common` and `starknet-rust`, and `client` already depends on it, so
only a `gateway` edge and one DAG-policy line are missing. That was considered
and rejected: it would move ~35 lines of glue, add a crate edge, and leave the
part that actually matters exactly where it already is.

## Invariants

- The tip is always locally chosen. No block body can inject one.
- A `ResolvedFeeBounds` only exists if it passed the caller's approval, so
  holding one proves the approval held for the value as returned.
  `#[non_exhaustive]`
  stops another crate constructing one from scratch, but the fields are public
  and the type is `Copy`, so it is a value type, not a capability token — a
  caller can copy one and edit it. That is deliberate: the approval is the
  caller's own policy, and one who edits past it could equally have raised
  `max_fee_fri`. It defends against the endpoint, never against the caller.
- `ResolvedFeeBounds::total_fri()` mirrors the protocol formula:
  `sum(amount * price) + tip * l2_gas`. Arithmetic is checked throughout;
  overflow is a rejection, never a wrap.
- Approval is inclusive: `total == max_fee_fri` is allowed.
- The transaction hash is computed locally from the prepared transaction and is
  the only hash used. The endpoint's reported `transaction_hash` is never read.
  Comparing the two and erroring on mismatch would be worse on both counts: it
  strands a transaction that is already broadcast (the caller loses the one
  correct hash and may retry into a double-submit), and it is unnecessary,
  because the hash is a deterministic function of the signed payload. Tracking a
  substituted hash could surface another transaction's successful receipt as
  this one succeeding; tracking the local hash can at worst time out.
- The nonce is *not* pinned. A deploy attempt that reverts is still included in
  a block and bumps the nonce of an account that is still undeployed, so
  `check_deployed` says nothing about it; `fetch_nonce` maps ContractNotFound to
  zero itself. The nonce is signature-committed, so an endpoint lying about it
  costs availability, never money — it is outside this approval's threat model.

## Deliberately not promised

- The approval bounds what can be *signed*, not what a sequencer charges. An
  honest sequencer charges less.
- The approval applies to the **resolved bound**, not the raw estimate. That is
  deliberate:
  the bound is what a sequencer may actually charge, so it is the quantity a
  spend limit has to constrain. The 1.5x amount and 1.5x price multipliers
  compound, so the value shown for approval can be up to 2.25x the raw estimate.
- The approval constrains an endpoint that **inflates** the fee. One that
  **deflates** `l2_gas_consumed` is not addressed: the bound resolves well under
  the approval, is signed, and the transaction then runs out of L2 gas and
  reverts — with the consumed gas still charged. That is a slow drain plus a
  denial of service, bounded by real gas rather than by the balance. A minimum
  floor, or comparing successive estimates, would be the missing control.
- Pinning the tip to 0 trades inclusion for safety. Under the v0.14 tip-ordered
  mempool a zero-tip transaction sorts below tipped ones, so callers who need
  inclusion during congestion must set `FeeBounds::tip`; the resolved approval
  amount includes `tip * l2_gas`. There is no safe default tip, because a
  non-zero default would reintroduce a number the caller did not choose.

## Failure modes

Missing or insufficient approval is a `KmsError::TransactionError` beginning
with `fee approval required:` and carrying the resolved total and, when present,
the approved ceiling in exact FRI and formatted STRK. The gateway classifies it
as non-retryable `InvalidRequest`. `KmsError` is not `#[non_exhaustive]`, so
adding a dedicated variant would be a breaking public-enum change; the stable
prefix preserves the patch-release surface while giving hosts one flag to route
into confirmation UI.

## Tests

`crates/common/src/fee/tests.rs` unit-tests the resolution laws: no default
approval, proof-sized traffic requiring then accepting user approval, tip
pinned to zero, multipliers applied, explicit fields overriding, tip counted,
overflow rejected, nonsense multipliers rejected, and inclusive approval.

`crates/client/tests/fee_bounds_hostile_rpc.rs` covers both client paths and
`crates/gateway/tests/fee_bounds_hostile_rpc.rs` covers the gateway, additionally
asserting the refusal is classified non-retryable. Each uses a canned-response
JSON-RPC server that answers `starknet_estimateFee` with an inflated
`l2_gas_price` and asserts `Wallet::execute` refuses before signing, with a
submit counter that must stay at zero. It fails against the pre-fix code (the
transaction is submitted at a bound of ~2359 STRK, from a ~1048 STRK estimate)
and fails again if the approval check is removed. Successful approved cases
inspect the submitted JSON to assert `tip = 0`, assert no block-body request was
made, and return a fabricated transaction hash that must not be tracked. Those
assertions cover wallet execution, client deployment, and gateway deployment.
