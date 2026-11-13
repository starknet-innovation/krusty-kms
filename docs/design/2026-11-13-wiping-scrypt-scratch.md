# Wiping scrypt scratch

## Context

The locked RustCrypto `scrypt` 0.12.0 KDF creates ordinary `Vec<u8>` buffers
for the PBKDF2 input block and ROMix scratch. The first ROMix block contains a
cheap password verifier. Scrubbing only the final derived key does not remove
that verifier from freed process memory.

## Design

`krusty-kms` now runs the same PBKDF2 and portable BlockMix/ROMix algorithm
with B, V and T owned by `Zeroizing<Vec<u8>>`. The portable routines are adapted
from RustCrypto `scrypt` 0.12.0 (MIT OR Apache-2.0). Its accelerated SSE2 and
WASM SIMD routines use intrinsics that require `unsafe`, while this crate
forbids unsafe code. We retain `scrypt::Params` to preserve parameter checks
and compare derived outputs against the locked implementation across salts,
passwords, lane counts and output lengths.

The `salsa20/zeroize` feature wipes the temporary Salsa core state on drop.
The secret-hygiene guardrail rejects direct calls to upstream `scrypt::scrypt`
from native KMS source, so a later KDF refactor cannot silently bypass the
wiping implementation.

The copied portable BlockMix and ROMix carry source attribution in their
module headers. Their upstream MIT and Apache-2.0 license texts are included
in the published `krusty-kms` crate package.

This keeps the existing encrypted-key and keystore wire formats. No public API
or dependency range changes. The additional zeroing costs one pass over the
scratch and the portable BlockMix may be slower than the upstream SIMD paths.

## Verification

The focused differential test covers multiple parameter shapes. The native
memory-inspection gate checks the 1 MiB ROMix allocation at deallocation
after successful encryption, successful decryption and failed decryption.
Its isolated control build disables the V-buffer wipe and must observe a
nonzero free in all three paths; the clean build must observe zero in all
three. A compile-time test pins `SalsaCore`'s `ZeroizeOnDrop` implementation.
The native and WASM canonical checks cover existing keystore vectors and
cross-boundary behavior. The allocator probe does not claim to wipe compiler
registers or small temporary copies inside underlying crypto dependencies.

An Apple ARM release build with ten `N=2^15, r=8, p=1` direct encryptions
took 442 ms on the base commit and 539 ms with wiping, about 22% longer in
separate local runs. This is indicative rather than a cross-platform bound;
the portable routine may cost more where the locked crate uses SIMD.
