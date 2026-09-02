# Local fee ceilings for signed resource bounds

## Problem

`Wallet::execute`, `deploy_oz_account`, and the gateway's `deploy_open_zeppelin`
let `starknet-rs` fill V3 resource bounds from the RPC's `estimate_fee` times a
1.5 multiplier. The RPC is untrusted for rates, so an inflated estimate becomes
a signed fee authorisation the KMS never bounded (audit finding M-3).

## Contract

- `krusty_kms_common::fee::ResourceBoundsCeiling { l1_gas, l2_gas, l1_data_gas }`
  holds one `MaxBound { max_amount, max_price_per_unit }` per dimension.
  `new` rejects any zero field; `admit_estimate` scales raw `(consumed, price)`
  figures exactly as `starknet-rs` does and returns the `ProposedResourceBounds`
  that may be signed, or a `FeeCeilingError` naming `dimension.field`.
- `Wallet::with_fee_ceiling(ceiling)`, `deploy_oz_account_with_fee_ceiling(..,
  Option<&ceiling>)`, and `StarknetGatewayBackend::with_deploy_fee_ceiling(ceiling)`
  apply it. Every existing signature is unchanged.
- Flow with a ceiling: estimate through the RPC, scale, admit, pin all six
  bounds explicitly on the `starknet-rs` builder, then send.

## Laws

1. Signed bounds are at or below the ceiling in every field, always: the pinned
   values are the admitted proposal, and `starknet-rs` skips its own estimate
   once all six are set.
2. Absent ceiling is exactly the previous behaviour: the unbounded code path is
   untouched.
3. An admitting ceiling signs the same bounds the unbounded path would have
   signed (same `f64` arithmetic and `u64` price range as `starknet-rs`).
4. Reject, never clamp: clamping would let the RPC steer bounds to the ceiling.
5. Zero ceiling fields are invalid, and `admit` re-validates so a ceiling built
   by literal or deserialization fails closed.
6. The worst-case fee a ceiling permits is the sum over dimensions of
   `max_amount * max_price_per_unit`.

## Failure behaviour

The client reports `KmsError::FeeEstimationFailed("fee ceiling: ...")`; the
gateway reports a non-retryable `GatewayErrorCode::InvalidRequest` with the same
message. The typed `FeeCeilingError` is stringified at those boundaries because
`KmsError` and `GatewayErrorCode` are exhaustive enums and a new variant would be
a semver-major change.

## Alternatives considered

- A per-request ceiling on the gateway and oracle (`DeployAccountRequest.fee_ceiling`)
  needs a new public field on a literal-constructed struct and a new
  `GatewayBackend` method; both break semver on `domain` and `gateway`. The
  backend-level policy covers the deploy path today; the request field is the
  follow-up once a minor release is planned.
- A total-fee cap (`max_total_fee_fri`) is deferred; law 6 already bounds it.
- Shared `starknet-rs` glue is impossible because the gateway cannot depend on
  `client` or `wallet-api`, so the small pin helper exists in both crates.

## Testing

`crates/common/src/fee/tests.rs` checks the laws directly: equal-to-ceiling
passes, one-over in each of the six fields fails naming it, zero fields are
rejected, a deserialized zero ceiling fails closed, and scaling matches the
`starknet-rs` multiplier. Client and gateway tests build the broadcast request
offline via `prepared().get_*_request(true, true)` and assert the signed
`resource_bounds` equal the admitted proposal, and that over-ceiling estimates
are rejected with the mapped error. No test touches the network.
