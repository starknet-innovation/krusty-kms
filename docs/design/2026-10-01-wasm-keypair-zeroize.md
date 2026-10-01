# Zeroize WASM keypair private keys on drop

Date: 2026-10-01. Status: proposed. Origin: found while debugging a downstream
consumer's WASM heap corruption, which meant reading what freed objects leave
in linear memory.

## Problem

`WasmKeypair`, `WasmStarkXOnlyKeypair`, and `WasmNostrKeypair` each own a
`private_key: String` in WASM linear memory. When JS calls `free()`, or the
wasm-bindgen `FinalizationRegistry` collects the object, the Rust value is
dropped and its buffer goes back to the allocator with the key still in it.
It stays there until a later allocation reuses those bytes. Building the
package from `main`, constructing each type from JS with a marker key and
calling `free()` leaves 56 of the key's 58 bytes in place (the allocator's
free-list header takes the first 8).

The core crates already wipe secrets they own (`SecretFelt`,
`NostrKeyPair`, `Zeroizing` mnemonics). The WASM boundary types did not.

## Change

The three types derive `Zeroize` and `ZeroizeOnDrop`, with `#[zeroize(skip)]`
on their public-key fields, the same shape as `krusty_kms::NostrKeyPair`. The
WASM crate gains the workspace `zeroize` dependency (already in the lockfile;
the only lockfile change is the new edge).

## Interface we keep

The JS surface is unchanged: the same classes, constructors, getters, setters,
and `publicKeyHex`. The export snapshot changes only because it records each
type's derive list. The type tests move to `types/tests.rs` so that
`types.rs` does not grow past its ratchet; its file-size baseline drops from
562 to 498 lines. Rust code can no longer move a field out of these types
(they now implement `Drop`), which affected one test helper; the crate is not
published to crates.io.

## Laws

- Each type implements `ZeroizeOnDrop`, checked at compile time by
  `wasm_keypair_types_zeroize_on_drop`.
- `zeroize()` empties `private_key` and leaves the public key fields intact
  (`wasm_keypair_zeroize_wipes_only_the_private_key`).
- After `free()` on a package built from this change, the key's bytes at its
  former location read as zeros.

## Not covered

- Each read of the `private_key` getter (`getter_with_clone`) clones the key
  into a temporary Rust `String` that the glue frees with
  `__wbindgen_free` without wiping it.
- The setter drops the previous key without wiping it.
- The JS string the getter returns cannot be wiped.

Closing the getter copy would mean replacing `getter_with_clone` on
`private_key` with a hand-written getter that hands JS a view of the owned
buffer. That changes the export surface, so it belongs in its own change.
