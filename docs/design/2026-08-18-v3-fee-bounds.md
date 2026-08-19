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

One root cause, four sites. Three are fixed here: `Wallet::execute`,
`deploy_oz_account`, and the gateway's `deploy_open_zeppelin`.

The fourth, `ControllerWallet` (`crates/controller/src/wallet.rs`), is
deliberately out of scope. Its `execute` passes an endpoint estimate straight
through unbounded, and both it and `deploy` track the endpoint's reported hash —
the same two defects, so anything holding a `dyn WalletExecutor` loses both
protections when the concrete type is `ControllerWallet`. Fixing it properly
means either threading `FeeBounds` through the Cartridge `account_sdk` builder,
whose fee semantics differ and may be paymaster-backed, or moving the bound to
the `WalletExecutor` trait — a breaking change to a shared boundary. The crate
is excluded from the workspace and its SDK path is behind a non-default feature.
Tracked separately rather than widened into this change.

## Interface

`krusty_kms_common::fee::FeeBounds` — what a caller is willing to spend. All
three paths resolve through it; no existing signature changed.

```rust
let wallet = Wallet::from_signing_key(..)?
    .with_fee_bounds(FeeBounds { max_fee_fri: 5 * ONE_STRK_FRI, ..Default::default() });
```

Also `deploy_oz_account_with_bounds` and
`StarknetGatewayBackend::with_fee_bounds`. `FeeBounds::default()` pins the tip
to 0 and caps the total at `DEFAULT_MAX_FEE_FRI` (1 STRK), so callers that never
mention fees are protected without a code change.

Two resolution modes, both funnelling through one ceiling check:

- `explicit()` — `Some` only when all six gas fields are set, in which case no
  estimate is requested and the endpoint contributes nothing to the signature.
- `resolve(&estimate)` — explicit fields win; the rest are the estimate scaled
  by the multipliers (1.5, matching prior starknet-rs behaviour).

`FeeEstimateInput` is six plain scalars rather than `starknet_rust::FeeEstimate`,
which keeps `krusty-kms-common` free of a Starknet dependency and the resolution
logic pure. Each of `client` and `gateway` maps its own estimate into it, and the
builder-setter chain plus `estimate_input`/`resolve_bounds` are duplicated
across the three sites, and that is intentional.

The security-critical part is not duplicated. The resolution order — scale by
the multipliers, then check the ceiling — lives once, in `FeeBounds::resolve`
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
- A `ResolvedFeeBounds` only exists if it passed the ceiling check, so holding
  one is proof the ceiling held for the value as returned. `#[non_exhaustive]`
  stops another crate constructing one from scratch, but the fields are public
  and the type is `Copy`, so it is a value type, not a capability token — a
  caller can copy one and edit it. That is deliberate: the ceiling is the
  caller's own policy, and one who edits past it could equally have raised
  `max_fee_fri`. It defends against the endpoint, never against the caller.
- `max_fee_fri()` mirrors the protocol formula:
  `sum(amount * price) + tip * l2_gas`. Arithmetic is checked throughout;
  overflow is a rejection, never a wrap.
- The ceiling is inclusive: `total == max_fee_fri` is allowed.
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
  costs availability, never money — it is outside this ceiling's threat model.

## Deliberately not promised

- The ceiling bounds what can be *signed*, not what a sequencer charges. An
  honest sequencer charges less.
- `estimate_fee` remains a separate read-only round trip. A caller that displays
  an estimate and then submits still makes two estimate calls against different
  block states; the signed one is now ceiling-bounded, which is the security
  property. The display mismatch is a UX matter, not a drain.
- `DEFAULT_MAX_FEE_FRI` (10 STRK) is a judgment call, not a measured one — no
  gas figures for these operations are recorded in this repo. It is sized for
  proof verification, the heaviest workload here, and
  `default_admits_a_proof_sized_transaction` pins that intent so a later change
  fails in the test suite rather than against honest mainnet traffic. It should
  still be checked against a real Sepolia estimate before release.
- The ceiling applies to the **bound**, not the estimate. That is deliberate:
  the bound is what a sequencer may actually charge, so it is the quantity a
  spend limit has to constrain. But the 1.5x amount and 1.5x price multipliers
  compound, so the 10 STRK ceiling admits an *estimated* fee up to ~4.4 STRK.
- The ceiling constrains an endpoint that **inflates** the fee. One that
  **deflates** `l2_gas_consumed` is not addressed: the bound resolves well under
  the ceiling, is signed, and the transaction then runs out of L2 gas and
  reverts — with the consumed gas still charged. That is a slow drain plus a
  denial of service, bounded by real gas rather than by the balance. A minimum
  floor, or comparing successive estimates, would be the missing control.
- Pinning the tip to 0 trades inclusion for safety. Under the v0.14 tip-ordered
  mempool a zero-tip transaction sorts below tipped ones, so callers who need
  inclusion during congestion must set `FeeBounds::tip` and raise `max_fee_fri`
  to cover the `tip * l2_gas` term. There is no safe default tip, because a
  non-zero default would reintroduce a number the caller did not choose.

## Failure modes

Every rejection is `KmsError::TransactionError` carrying both the resolved total
and the ceiling. `KmsError` is not `#[non_exhaustive]`, so a dedicated variant
would force a minor bump; reusing the existing variant keeps this releasable as
a patch.

## Tests

`crates/common/src/fee/tests.rs` unit-tests the resolution laws: tip pinned to zero by
default, multipliers applied, explicit fields overriding, tip counted toward the
ceiling, overflow rejected, nonsense multipliers rejected, ceiling inclusive.

`crates/client/tests/fee_bounds_hostile_rpc.rs` covers both client paths and
`crates/gateway/tests/fee_bounds_hostile_rpc.rs` covers the gateway, additionally
asserting the refusal is classified non-retryable: `map_kms_error` matches by
substring and would otherwise land it in `RpcDegraded`, advertising a
deterministic refusal as a transient hiccup a client should retry. Each: a
canned-response JSON-RPC server answers `starknet_estimateFee` with an inflated
`l2_gas_price` and asserts `Wallet::execute` refuses before signing, with a
submit counter that must stay at zero. It fails against the pre-fix code (the
transaction is submitted at a bound of ~2359 STRK, from a ~1048 STRK estimate)
and fails again if the ceiling check is removed, so it is load-bearing rather
than tautological. It answers
`starknet_getBlockWithTxs` too, so a regression that reintroduces the median-tip
path still reaches submission and is caught by the counter rather than by an
incidental transport error.
