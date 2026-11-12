# Reproducible mnemonic memory inspection

This suite checks selected mnemonic secret representations in optimized builds.
It uses only throwaway runtime fixtures; it never reads wallet files or accepts
real secrets. A clean scan is evidence for the recorded cases and build, not a
portable erasure guarantee.

## Run

Prerequisites: Python 3.8+, rustup/Rust, a native C compiler and `ar`; Node 22 and
the locked `wasm-bindgen` CLI are also needed for WASM. Install the WASM target
and CLI using the repository helper:

```sh
rustup toolchain install 1.100.0 --profile minimal --component rustfmt
rustup target add wasm32-unknown-unknown --toolchain 1.100.0
RUSTUP_TOOLCHAIN=1.100.0 bash .github/scripts/install-wasm-bindgen-cli.sh
RUSTUP_TOOLCHAIN=1.100.0 bash tools/check.sh memory
```

`memory-native` and `memory-wasm` run one backend. The selected toolchain must
already be installed. To use the current installed stable instead, omit
`RUSTUP_TOOLCHAIN`; reports record its actual compiler version.

Reports default to `target/memory-inspection/*.json`. Override their directory
with `KMS_MEMORY_REPORT_DIR`. Only top-level JSON reports should be retained as
CI artifacts; the `build/` subdirectory contains ordinary build products.

## Control and source identity

The common runner copies current **tracked-file contents**, including staged
additions, into two private temporary directories. Stage new source files
before running locally. It records the commit and a digest of the copied
contents, and rejects differing snapshots. Ignored credentials, build output
and user worktrees are not copied. Build/profile environment overrides are
cleared and their names recorded so they cannot silently change optimization.

The control snapshot removes exactly the one post-call `scrub_stack()` call in
`scrubbed`. An unexpected source shape fails for review. No production feature,
environment variable or exported function disables wiping. Temporary source
copies are deleted after the run.

The control is mandatory: a scanner that cannot detect the selected remnants
must fail as inconclusive. A clean result requires the normal build to have no
searched remnants. Backend reports contain per-case/per-pattern counts and
toolchain/profile metadata; neither raw snapshots nor fixture values are saved.

## Observers and limits

- [Native](native/README.md): a separate thread obtains a bounded inactive-stack
  snapshot through OS APIs while the worker waits. It validates full reads,
  mapping bounds, matcher calibration and positive controls. It excludes the
  active caller frame and does not inspect the heap.
- [WASM](wasm/README.md): Node inspects linear memory after each exported call.
  The backend documents exactly which known live input/output ranges it owns
  and excludes; other matches, including freed allocations, remain visible.

The backend documents supported operating systems, architectures, cases and
patterns. Unsupported OS reads, incomplete records and failed controls are
errors. CI records Linux x86_64 native, macOS aarch64 native, and WASM results.
Consumer compilers, optimization settings, stack layouts and inputs can differ.
Register spills, other secret representations and untested normalization/error
paths are not proven clean by these measurements.

The production overwrite itself needs at least 32 KiB of extra stack headroom.
Small custom/foreign-thread stacks can overflow. See the
[design note](../../docs/design/2026-11-12-bip39-memory-hygiene.md) for production
scope and normalization exclusions.
