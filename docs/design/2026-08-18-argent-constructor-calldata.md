# Design: version-correct Argent constructor calldata

Date: 2026-08-18

## Problem

`ArgentAccount::build_constructor_calldata` returned `[0, public_key, 0]` for
every Argent class hash, so every Argent address this crate derived was wrong on
all three shipped surfaces: `deriveArgentAccountAddress` (npm), gateway and
oracle `derive_account`, and account discovery.

Read from the deployed class ABIs:

- v0.4.0 takes `constructor(owner: Signer, guardian: Option<Signer>)`.
  `Signer::Starknet` is variant `0`, and `Option::None` is variant `1` (`Some` is
  `0`), so the calldata is `[0, public_key, 1]`.
- v0.3.0 and v0.3.1 take `constructor(owner: felt252, guardian: felt252)` —
  exactly two felts, `[public_key, 0]`.

The old trailing `0` encodes a truncated `Option::Some`, which fails Cairo
deserialization. The addresses it produced were therefore not merely different
accounts; they were permanently undeployable.

Confirmed against Sepolia: the corrected derivation reproduces a live v0.4.0
account for the repo's test mnemonic (`ARGENT_ACCOUNT_ADDRESS`), while the
previous address returns `Contract not found`. Because a contract address is
`hash(prefix, 0, salt, class_hash, hash(calldata))`, reproducing a known
on-chain address is a preimage proof of the calldata.

The bug had been observed and misdiagnosed as "Argent's server provided the
salt". Three oracles pinned the wrong encoding (a unit test, the account-class
fixture, and the starknet.js cross-test, which hand-copied `[0, pk, 0]`), and two
discovery tests asserted the derived address was *not* the real account.

## Interface

`build_constructor_calldata` dispatches on class hash: the two v0.3.x hashes get
`[public_key, 0]`, v0.4.0 gets `[0, public_key, 1]`. No signature changes and no
call site changes — all four surfaces route through this one method.

`ArgentAccount::calculate_address` is now overridden to return
`KmsError::InvalidClassHash` unless the class hash is one of the three known
Cairo-1 hashes. This is the one deliberate behaviour change beyond correctness:
Argent's constructor shape is version-dependent, and `getAccountClassHashes()`
publishes Cairo-0 proxy hashes that take a third shape
(`[impl, selector("initialize"), 2, owner, guardian]`), so a guessed layout
yields exactly the undeployable address described above. For a recovery library,
an error beats a confidently wrong address.

`known_class_hashes()` now returns a private `KNOWN_CLASS_HASHES` const array
rather than re-parsing three hex strings per call. Allowlist and layout dispatch
read the same table, so they cannot drift, and the gateway no longer parses and
allocates on every request that names a class hash.

## Invariants

- A class hash is either in `KNOWN_CLASS_HASHES` with a known constructor
  layout, or address derivation fails. There is no third state.
- Adding an Argent version means adding it to `KNOWN_CLASS_HASHES` *and* to the
  layout dispatch; the allowlist cannot silently accept a hash whose layout is
  unknown.
- `Felt::from_hex_unchecked` is used for the parsed consts, but each is pinned
  by a test that parses the same string with the checked `Felt::from_hex`, so a
  malformed constant cannot pass unnoticed.
- Braavos address derivation still always uses the base deployment class hash;
  the fixture runner asserts each Braavos vector pins that hash rather than
  deriving from whatever the vector supplies.

## Guardrail baseline

`account_class.rs` had grown past its file-size ratchet baseline. Rather than bump
it, the unit tests moved to `account_class/tests.rs` — the approach taken in #97
("split ElGamal FFI tests into module"). The baseline therefore *drops* from 585 to
416 lines, tightening the ratchet rather than loosening it, and no new oversized
file is introduced. The FFI and WASM surface snapshots are unchanged.

## Failure modes

Callers passing a custom or legacy Argent class hash — including via the
gateway's `allow_unlisted_class_hash` — now receive `InvalidClassHash` instead of
an address. That flag remains meaningful for OpenZeppelin and Braavos, whose
constructor is `[public_key]` regardless of version.

Any Argent address cached from an earlier release is wrong and must be
discarded. It must never be treated as a receive address: the contract cannot be
deployed, so funds sent there are unrecoverable. This crate cannot itself deploy
or fund an Argent account (`deployment_descriptor` exists only for
OpenZeppelin and multisig), so the exposure is to integrators that displayed a
derived address.

OpenZeppelin, Braavos, and the Argent Cairo-0 proxy candidate path in
`discovery::generate` are unaffected.
