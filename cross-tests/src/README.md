# Cross-language test harness

> **Do not fund, reuse, or import the keys in `reference-values.json`.**
>
> The reference values include a **publicly known test private key** (and the
> Stark public key and signatures derived from it) so the Rust and TypeScript
> stacks can be compared deterministically. Anyone can read it, so it protects
> nothing: never derive a funded account from it and never load it into a
> wallet.

The `verify-*.ts` scripts compare Rust outputs against starknet.js. Some
expected values are pinned on the first successful run and must then be
committed; the scripts say so when that happens.
