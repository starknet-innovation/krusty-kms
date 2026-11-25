# Secret-returning derivation and signing with a known public key

Status: proposed for the next 4.x minor. Tracks
[issue 228](https://github.com/starknet-innovation/krusty-kms/issues/228).

## Context

Issue 228 lists secret-handling changes that were deferred as breaking:

1. Several derivation functions return a plain `Felt`, and
   `derive_nostr_private_key` returns a bare `[u8; 32]`. Both types are `Copy`,
   so the copy in the callee's return slot cannot be wiped by the caller.
2. `sign_stark_hash` recomputes the public key from the private key on every
   call: one more variable-time multiplication by the secret.
3. The STRK20 viewing-key reduction and fold ran on `num-bigint`: variable-time,
   with heap buffers that are never wiped.
4. `StarkCurve::mul_generator` is described as regularized, but it is not
   constant-time for a secret scalar.

Changing a return type or a parameter list is breaking, and a breaking change
does not merge inside a major. This note covers what can ship in 4.x.

## Design

### New functions next to the old ones

| Existing (unchanged) | Added | Returns |
| --- | --- | --- |
| `derive_private_key_with_coin_type` | `derive_secret_key_with_coin_type` | `SecretFelt` |
| `derive_argent_legacy_private_key` | `derive_argent_legacy_secret_key` | `SecretFelt` |
| `derive_stark_from_eth_key` | `derive_stark_secret_key_from_eth_key` | `SecretFelt` |
| `grind_key` | `grind_secret_key` | `SecretFelt` |
| `fold_strk20_viewing_key` | `fold_strk20_secret_viewing_key` | `SecretFelt` |
| `derive_scoped_strk20_viewing_key` | `derive_scoped_strk20_secret_viewing_key` | `SecretFelt` |
| `derive_nostr_private_key` | `derive_nostr_secret_key` | `Zeroizing<[u8; 32]>` |
| `sign_stark_hash` | `sign_stark_hash_with_public_key` | `StarkSignature` |

Each existing derivation and fold function is now a one-line wrapper that
copies the value out of the new one, so the two cannot drift: outputs and
rejections are shared by construction, and tests assert the equal outputs.
`sign_stark_hash` and `sign_stark_hash_with_public_key` share the validation
and signing helper instead; a test asserts equal `(r, s)`. Key and address
derivation is unchanged for every input.

The existing functions are not marked `#[deprecated]` here. Doing so would
force every caller in the workspace, including the WASM and C ABI crates, to
move in the same change. Their docs point to the replacements.

Two functions get no secret variant: `derive_private_key` is
`derive_secret_key_with_coin_type` with `TONGO_COIN_TYPE`, and the unscoped
`derive_strk20_viewing_key` is kept only for compatibility.

Inside `krusty-kms`, `derive_keypair_with_coin_type`, `derive_nostr_keypair`
and account discovery now use the new functions, so the key moves into its
wiping owner instead of being copied through a `Felt`.

### `sign_stark_hash_with_public_key`

Inputs: private key, the signer's public key (x-coordinate), hash. Output: the
same `(r, s)` as `sign_stark_hash`, with the supplied public key.

The fresh signature is verified under the supplied public key with the raw
Stark ECDSA check, which uses no secret, and the call fails if it does not
verify. Invariant: a returned signature is valid for the returned public key.

The check catches a key passed by mistake: an unrelated key verifies only
with negligible probability. It is not proof that the public key belongs to
the private key. Stark verification accepts either point with a given x, so
for a signature `(r, s)` over a non-zero hash `z`, the x-coordinate of
`(d + 2z/r)·G` also verifies. Anyone who sees the signature can compute that
point, and the signature really is valid under it, so accepting it releases
nothing `sign_stark_hash` would not. A test pins this behavior. A caller that
needs the public key to be authentic derives it with `stark_public_key`.

The verifier also rejects a signature whose `s` has an inverse of 2^251 or
more, which the signer does not check. That happens for about one signature
in 2^55 and is reported as the same error.

The raw check is used instead of `verify_stark_signature` so that a zero hash
is still signed, as `sign_stark_hash` does. Forging a zero-hash signature
needs a free choice of `(r, s)`; here they are our own.

Cost: one verification (two variable-time multiplications on public values)
replaces one variable-time multiplication by the private key. The call is
slower; it trades speed for one fewer secret-dependent operation.

### STRK20 fold

`n` and `floor(n / 2)` are `NonZero<U256>` constants. Secret hashes are read
into `Zeroizing<U256>`, reduced with `Uint::rem`, and folded by computing both
`x` and `n - x` and selecting by mask (`CtLt`, `CtSelect`). The out-of-range
cases (`0`, `floor(n / 2)`, `ceil(n / 2)`) map to 1 by the same kind of
selection. No branch in the reduction or fold depends on the key.

The old `num-bigint` arithmetic is kept in the tests as a reference and
compared over the fold's edge cases, hashes in `[n, p)` and at both ends of
the field, and 256 pseudorandom inputs, alongside the existing known-answer
vectors.

Not covered: the hash result before it is wrapped, temporaries inside
`crypto-bigint`, and compiler-made copies on move. Not constant-time: the
hashing and signature verification that run before the fold, and the
conversions between `Felt` and bytes (lambdaworks Montgomery form) on the way
in and out.

### `mul_generator`

Documentation only. lambdaworks' `operate_with` returns early when either
operand is the identity, so the accumulator's first iterations are cheaper
until the lowest set scalar bit. The docs on `mul_generator`, `mul` and the
private `scalar_mul` now say so. Removing the leak needs a different addition
formula or a blinded accumulator in `krusty-kms-crypto`, which is a larger
change to a primitive every proof uses; it is left for a separate proposal.

## Failure modes

- A wrong or non-curve public key passed to `sign_stark_hash_with_public_key`
  returns `KmsError::CryptoError`; no signature is released.
- The new derivation functions return the same errors as the old ones.

## Dependencies and surfaces

No dependency or version-range change: `crypto-bigint` was already a
`krusty-kms` dependency, and `num-bigint` stays for the Bitcoin module. The
WASM export list and the C ABI header are unchanged.

## Follow-up in 4.x

Move the WASM, C ABI and gateway callers to the new functions. That is not
breaking, but a crate that starts using them must raise its `krusty-kms`
requirement to the release that adds them, so it follows that release. Until
then the new functions are used only inside `krusty-kms`, and nothing in the
workspace calls `sign_stark_hash_with_public_key`.

## Left for the next major

- Remove or change the `Felt` / `[u8; 32]` returning functions.
- Decide whether `sign_stark_hash` itself should take the public key.
