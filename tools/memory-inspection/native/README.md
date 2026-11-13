# Native stack inspection

This standalone, unpublished harness checks optimized `krusty-kms` code on
macOS/Linux, aarch64/x86_64. It requires Python 3, rustup, a C compiler and `ar`.
Unsupported systems or denied/partial OS reads fail; they never count as clean.
The committed standalone lockfile pins dependencies. Build profile is release
(`opt-level=3`, debug information retained); reports include `rustc -vV`, the C
compiler, OS and architecture. It is separate from production crate features.

The common memory-inspection runner supplies clean and control source snapshots.
For either snapshot:

```sh
python3 tools/memory-inspection/native/run.py \
  --source-root /absolute/path/to/snapshot --mode clean \
  --toolchain stable --report /absolute/path/to/native-clean.json
```

Use `--mode control` only with the common runner's narrowly validated temporary
source mutation removing the single `scrub_stack()` call from `scrubbed`. No
production insecure feature is introduced. Both modes must pass: a control with
no detected remnant fails as inconclusive. `--target-dir` optionally shares build
artifacts between source snapshots; Cargo rebuilds changed sources.

## What is measured

For each of four runtime-random fixtures (two 16-byte and two 32-byte entropies),
the harness exercises entropy encoding, valid mnemonic validation, and seed
derivation, checking outputs against `bip39`. Passphrases include a character
changed by NFKD. Reference data and expected patterns are built on the observer
thread, outside the inspected stack. Nothing reads a real wallet or user secret.

Each operation runs on a fresh 2 MiB pthread stack. A fixed Rust callback captures
its current stack boundary just before entering production code. Caller-owned
returned seed/phrase slots live in that callback's frame, above the boundary,
and are excluded. The C leaf boundary helper accounts for x86's pushed return
address; its compilation uses `-O2 -fomit-frame-pointer`. The worker checks its
stack mapping bounds, returns from the callback, and then waits using atomics
without further calls or writes into the inspected region.

The observer uses `mach_vm_read_overwrite` (macOS) or `process_vm_readv` (Linux)
to copy the 64 KiB below the captured boundary into an initialized byte buffer.
No Rust/C lvalue reads dead or uninitialized stack storage directly. Inspection
on another thread avoids overwriting the target frames with the scanner itself.
The measured range is twice the production 32 KiB scrub; those sizes are reported
separately. The full read and the captured boundary's stack membership must pass.

The scanner checks exact 16-byte entropy prefixes, 128 entropy bits represented
as boolean bytes, eight native-endian u16 word indices, the full derived seed,
and the complete HMAC inner key pad. Match calibration includes an unaligned
positive match and a corrupted-pattern negative match. Clean runs require zero
matches. Controls require a match for **every operation and fixture**, and report
counts per representation. A control need not expose every representation.

Only counts and toolchain metadata enter JSON reports. Raw snapshots and fixture
secrets are never printed or saved; buffers holding them zeroize on drop.

## Limits

This is an empirical regression test for the recorded compiler/target/profile,
not a proof about all optimizers, stack layouts, registers, or arbitrary memory.
It observes after the same callback output checks and zeroizing drops in both
modes; those steps may overwrite some remnants. The disabled-scrub control is
therefore mandatory. It does not scan heap allocations, active caller frames,
other threads, or storage below the 64 KiB window. It does not exercise invalid
mnemonic/error paths, random mnemonic generation, or the C ABI. WASM inspection
is a separate backend with its own range and ownership rules.
