# Wipe what `bip39` leaves behind

Date: 2026-11-12. Status: proposed.

## Problem

`bip39` 3.0.0's `zeroize` feature wipes the final `Mnemonic` and nothing else.
An internal review, reproduced on wasm32 and native aarch64, found these left
in memory after `mnemonic_to_seed` and `generate_mnemonic` returned:

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
   function from the same frame that overwrites 32 KiB of stack with
   `zeroize`. That second frame sits on the stack the first one used. The
   deepest remnant measured was under 2 KiB below the caller.
3. **`mnemonic_from_entropy`** is the one public entry for caller-supplied
   entropy, so the C ABI no longer calls `bip39` directly and the scrub covers
   it.
4. **No `std` on `bip39`.** In 3.0.0, `std` enables `serde/std` without `?`, so
   `Mnemonic: Serialize` was compiled in. We use `alloc` and `zeroize` only.
   `std` added nothing else we use (`impl std::error::Error`).

## Not covered

- The NFKD heap copy `parse` makes of a non-ASCII phrase. ASCII input, which
  covers all English phrases, makes none.
- Copies the compiler makes when it moves a value. On wasm32, one copy of
  the 64-byte seed is still left after `mnemonic_to_seed` returns it by
  value. Removing it would mean writing the seed straight into a
  caller-supplied buffer.
- Register spills, the heap, and any target whose `bip39` frames are deeper
  than 32 KiB.
- Variable-time word lookup inside `bip39` (binary search, table indexing).

## Compatibility

Additive. Seeds, phrases and accepted inputs are unchanged. A differential
test checks the seed against `bip39::Mnemonic::to_seed` for every word count,
for phrases on both sides of the 128-byte key boundary, and for passphrases
that NFKD changes, and Trezor and CPython `hashlib` vectors are checked too.
`bip39::Mnemonic` is not part of Krusty's public API, so losing `Serialize`
on it is not visible to callers.

## Verification

The review's memory harness, rerun against this branch: every remnant above
is gone, natively and on wasm32, except the wasm32 seed copy noted above.
With the scrub turned off, the bip39 remnants and our own SHA-2 midstates
come back, so the scrub is what removes them. Seed derivation takes about
0.75 ms natively, the same as `bip39`'s.
