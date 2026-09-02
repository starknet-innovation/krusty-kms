# SDK proof-generation fixtures

> **Do not fund, reuse, or import anything in this directory.**
>
> `prover-vectors.json` contains **publicly known test private keys** (owner and
> auditor keys) together with the balances, randomness, and proofs derived from
> them, so Tongo proof generation can be replayed deterministically across
> language ports. Anyone can read them, so any account they control is already
> compromised: never send funds to an address derived from them and never load
> them into a wallet.

The root `prover-vectors.json` is the generated copy written by
`crates/sdk/tests/generate_vectors.rs` (an `#[ignore]`d test); this file is the
committed copy replayed by `crates/sdk/tests/prover_vectors.rs`. Keep them in
sync and edit the JSON only through that tooling.
