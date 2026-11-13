# Wipe what `bip39` leaves behind

Date: 2026-11-12. Status: proposed.

## Problem

`bip39` 3.0.0's `zeroize` feature wipes the final `Mnemonic` and nothing else.
An internal review found these left in memory after `mnemonic_to_seed` and
`generate_mnemonic` returned. It reproduced the first two on wasm32 and native
aarch64 and found the third by reading the source:

- `to_seed`: its HMAC `ipad`/`opad` (the phrase XOR a constant when it fits
  one SHA-512 block, otherwise `SHA-512(phrase)`), both HMAC midstates and the
  running PBKDF2 block. `bitcoin_hashes` 0.14 engines have no `Drop`.
- `from_entropy` and `parse`: the entropy, its bits as `bool`s, and the word
  indices.
- `to_seed` and `parse`: an NFKD copy of a non-NFKD passphrase or phrase,
  freed without wiping.

Each one recovers the phrase or every key derived from it. No feature turns
the wiping on, and `bip39` caps `bitcoin_hashes` below 0.15, so a newer
`bitcoin_hashes` cannot help.

## Decision

1. **Own PBKDF2.** `zeroizing_hmac::pbkdf2_sha512` computes the single 64-byte
   block over `zeroizing_hmac::hmac`, hashing a password longer than one block
   into a wiped buffer first. `mnemonic_to_seed` feeds it the canonical phrase
   rebuilt from `Mnemonic::words()` and the passphrase NFKD-normalised by
   `unicode-normalization` (already in the graph through `bip39`). Both
   buffers are `Zeroizing` and sized up front, so they never reallocate.
2. **Stack scrub.** Each public function in `mnemonic` runs its `bip39` work in
   an `#[inline(never)]` frame, then calls a second `#[inline(never)]`
   function from the same caller that overwrites a 32 KiB stack buffer with
   `zeroize`. This is best-effort: Rust does not guarantee frame overlap.
   Control-backed probes check the selected representations on each recorded
   compiler/target/profile, rather than treating that layout as portable.
3. **`mnemonic_from_entropy`** is the one public entry for caller-supplied
   entropy, so the C ABI no longer calls `bip39` directly and the scrub covers
   it.
4. **No `std` on `bip39`.** In 3.0.0, `std` enables `serde/std` without `?`, so
   `Mnemonic: Serialize` was compiled in. We use `alloc` and `zeroize` only.
   `std` added nothing else we use (`impl std::error::Error`).

## Not covered

- The NFKD heap copy `parse` makes of a non-ASCII phrase. ASCII input, which
  covers all English phrases, makes none.
- The NFKD iterator's internal buffer, which moves to the heap for a run of
  more than four combining characters in the passphrase.
- Copies the compiler makes when it moves a value, including the seed that
  `mnemonic_to_seed` returns by value into the caller's frame.
- Register spills, the heap, and any target whose `bip39` frames are deeper
  than 32 KiB.
- Variable-time word lookup inside `bip39` (binary search, table indexing).

The overwrite reserves a real 32 KiB frame in addition to the caller's stack
needs. Small foreign/custom-thread stacks can abort from overflow; callers
must provide headroom. A 16 KiB requested thread stack overflowed in a release
Rust 1.100/macOS aarch64 reproduction while plain `bip39` validation succeeded.
That observation is not a portable minimum-stack measurement.

## Compatibility

Additive. Seeds, phrases and accepted inputs are unchanged. A differential
test checks the seed against `bip39::Mnemonic::to_seed` for every word count,
for phrases on both sides of the 128-byte key boundary, and for passphrases
that NFKD changes, and Trezor and CPython `hashlib` vectors are checked too.
`bip39::Mnemonic` is not part of Krusty's public API, so losing `Serialize`
on it is not visible to callers.

## Reproducible verification

The committed [`tools/memory-inspection`](../../tools/memory-inspection/README.md)
suite runs optimized native and WASM probes through `bash tools/check.sh memory`.
The runner snapshots tracked working-tree source, then removes exactly one
`scrub_stack()` call in the temporary control snapshot. Production source has
no insecure feature or runtime switch. Both builds must pass: clean builds
must have zero searched remnants, and controls must detect remnants for the
required cases. Unsupported reads and vacuous controls fail, not skip.

The native observer copies a quiescent worker's inactive stack through OS
APIs, without Rust/C reads of uninitialized storage. The Node observer scans
WASM linear memory after each operation, including freed heap, with only
precisely identified caller-owned input/output slots excluded. Each backend
documents its cases, patterns, ownership boundaries and unobserved regions.
Count-only JSON reports record compiler, target/profile and source hashes;
raw snapshots and fixture secrets are not retained.

This gives reproducible empirical regression evidence, not a proof that every
representation of every secret disappears on every consumer build. Seed and
phrase compatibility remain covered by the independent differential/vector
tests. CI additionally runs the probes on Linux native, macOS native and WASM.

CodeQL's fixed `"mnemonic"` salt prefix and long-HMAC-key SHA-512 reduction
are protocol requirements, not replacements for password stretching: see
[BIP-39](https://bips.dev/39/#from-mnemonic-to-seed) and
[RFC 2104 section 2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2).
The PBKDF2 loop still performs 2048 rounds. Public CPython vector constants
remain fixed so tests can compare against independent outputs. Individual
CodeQL dispositions record those reasons; no query or workflow is excluded.
