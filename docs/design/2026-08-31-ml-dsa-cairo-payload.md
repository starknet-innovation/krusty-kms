# Design: ML-DSA-65 key expansion and Cairo account payload

Date: 2026-08-31

## Problem

A Starknet account contract whose signing key is post-quantum (ML-DSA-65,
FIPS 204) cannot afford to recompute verification on chain: a full verify costs
about 1.07 G gas against a 100 M cap on `__validate__`. The contract therefore
verifies a *witnessed* form. The signer sends the matrix product `w` together
with two quotient witnesses `M'` and `K'` asserting

```text
A.z - c.T  =  w  +  Q*M'  +  (X^256 + 1)*K'
```

and the contract checks that identity at one random point.

Producing that payload is off-chain work no published crate can do. `ml-dsa`
(RustCrypto), `fips204`, `libcrux-ml-dsa` and the PQClean bindings all expose
only keygen, sign and verify; the NTT, `ExpandA`, `SampleInBall`, bit-unpacking
and `UseHint` are private in every one. The payload *is* the verification
transcript — the `w` rows the hints commit to must be the exact rows the
verifier computed — so a `verify() -> bool` that discards `w` cannot be composed
into it. Two other things are also blocked without this: the 925-felt packed key
that the account address commits to (a SHAKE expansion plus inverse NTT, not a
re-encoding), and the fee-estimation dummy signature.

## Interface

New module `krusty_kms_crypto::ml_dsa`, behind the off-by-default `ml-dsa`
feature. Five public functions and four constants:

- `ml_dsa_packed_key(public_key) -> Result<Vec<Felt>>` — the 925 felts
  (768 A, 154 T, 3 tr).
- `ml_dsa_key_commitment(public_key) -> Result<Felt>` — Poseidon over exactly
  those felts; the account contract's whole constructor argument.
- `ml_dsa_verify(public_key, &Felt, signature) -> bool` — FIPS 204 Algorithm 8.
- `ml_dsa_signature_payload(public_key, &Felt, signature) -> Result<Vec<Felt>>`
  — the 1,830-felt transaction payload.
- `ml_dsa_estimation_signature(public_key) -> Result<Vec<Felt>>` — a well-formed
  payload that verifies against nothing, for fee estimation under a query
  version.

The transaction hash is a `Felt`, never bytes. The message is that felt as 32
big-endian bytes with an empty FIPS 204 context; taking a `Felt` makes the
"minimal spelling" mistake — a shorter message is a different message —
unrepresentable at a call site.

## Dependencies

- `sha3` at **0.10.8**, optional, for SHAKE128/256. Deliberately not
  `workspace = true`: the workspace `sha3` is 0.12, whose restructure removed the
  XOFs entirely (only fixed-output SHA-3 and Keccak remain). 0.10.8 is already in
  the dependency graph via `starknet-rust-core`, so the feature adds no new crate
  to the build.
- `fips204` 0.4.6 (MIT OR Apache-2.0) as a **dev-dependency only**, to sign
  freshly generated keys so this verifier is checked against an implementation
  that is not itself. Never a runtime dependency: nothing here signs.

## Invariants

- Nothing in the module is secret-dependent. Every input is public — a public
  key, a public signature, a transaction hash. There is no signing, no key
  derivation, and no randomness, so nothing needs to be constant-time.
- Every decoder reads attacker-supplied bytes and returns `None` on any
  malformed shape. No panic, no unchecked index, no silent truncation. This
  includes `sample_in_ball`, whose rejection loop could in principle run off its
  272-byte stream.
- Hint positions within a row must be **strictly increasing**. RustCrypto's
  `ml-dsa` shipped GHSA-5x2r-hc65-25f9 for omitting exactly this, so it is its
  own named function.
- `ml_dsa_signature_payload` verifies first and re-checks the integer identity
  exactly before emitting anything. It errors rather than return a payload it
  could not prove, because the contract rejects a wrong payload with no
  diagnosis.
- Coefficients mod Q are `u32`, and every product widens to `u64` before
  reducing. The witness path is `i128`: it needs the unreduced integer
  convolution, whose accumulator reaches about 2^54.
- Each packed felt is two u128 halves composed as 32 big-endian bytes. The widest
  layout is six 20-bit fields (120 bits per half), so every composed value stays
  below 2^252 and is a valid felt with no field reduction anywhere.

## Failure modes and limits

- A wrong-length key or signature is refused by every entry point; `ml_dsa_verify`
  answers `false` rather than erroring, because its caller is gating a broadcast
  and wants one decision.
- The estimation signature is not a valid signature and must never verify. It
  clears the contract verifier's three early exits so the estimate includes the
  real validation cost, then fails the verdict; the contract tolerates that only
  under a query version, which the sequencer never executes. It keeps the *real*
  packed key so the measured path matches a real transaction and so it works
  against a class built before that tolerance existed.
- The `w`-row reuse between verification and the payload builder is load-bearing.
  Recomputing them independently would risk two different answers for the same
  signature, so verification returns a transcript rather than a bool.
- No external audit. The known-answer vectors come from ml-dsa-cairo
  (`py/gen_vectors.py`), the reference the Cairo verifier was written against,
  and the fixture pins a Poseidon digest per payload section so a drift localises
  to the section that moved.
- Feature-gated and off by default, so consumers that do not verify
  post-quantum accounts carry neither the code nor the SHAKE dependency.

## WASM surface

Four `wasm_bindgen` exports in `crates/wasm/src/ml_dsa.rs`, which together are
everything a wallet needs to run one of these accounts:

- `mlDsaKeyCommitment(publicKey) -> string`
- `mlDsaVerify(publicKey, transactionHash, signature) -> boolean`
- `mlDsaSignaturePayload(publicKey, transactionHash, signature) -> string[]`
- `mlDsaEstimationSignature(publicKey) -> string[]`

Hex strings in, hex felts out, matching the rest of the WASM surface
(`signStarkHash`, `poseidonHashMany`). `mlDsaVerify` answers `false` on malformed
input rather than throwing, because its caller is deciding whether to broadcast
and wants one outcome, not two; `mlDsaSignaturePayload` does the opposite and
throws, because a plausible-looking wrong payload is rejected on chain with no
diagnosis. The 925-felt packed key is deliberately **not** exported: it is an
intermediate of the other two, and no caller needs it alone.

There is no key generation and no signing here, and there will not be. The key
never leaves the phone's enclave, so this boundary only ever handles public
material.

`.github/guardrails/wasm-exports.txt` grows by exactly those four lines.
`crates/wasm/src/lib.rs` grows by one — the module declaration — which moves its
file-size ratchet entry from 403 to 404. The FFI header snapshot is unchanged.

## Verification

Beyond the crate's own tests, the built `--target nodejs` bundle was run against
the ml-dsa-cairo fixture and against the TypeScript implementation this replaces:
the commitment, all five payload section digests, the total payload digest, and
the full 1,830-felt payload all match both, and the estimation signature matches
the TypeScript felt for felt. That comparison is what retires the TypeScript
safely; it is not automated, because the TypeScript is being deleted.

## Not in this change

The C ABI (`crates/ffi`) exports for the phone targets, and the wallet-side
wiring that deletes the TypeScript implementation and drops
`@noble/post-quantum`.
