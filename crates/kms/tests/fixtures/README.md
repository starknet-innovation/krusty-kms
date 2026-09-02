# Test fixtures

> **Do not fund, reuse, or import anything in this directory.**
>
> These JSON vectors contain **publicly known test mnemonics and private
> keys**. They exist only so the derivation, hashing, and signing tests are
> deterministic and comparable across the Rust, Swift, JVM, Dart, and WASM
> ports. Anyone can read them, so any account they control is already
> compromised: never send funds to an address derived from them and never load
> them into a wallet.

The derivation, address, and signing files are byte-identical copies of the
shared vectors in `fixtures/vectors/` at the repository root; that directory's
README lists what each covers. The account-class, hashing, SNIP-12, and
transaction-hash parity vectors are consumed only by the `krusty-kms` tests.
Keep the shared copies in sync when regenerating vectors, and edit the JSON
only through the test tooling that consumes it.
