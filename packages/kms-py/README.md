# ghoul-kms (Python)

Python wrapper for the Ghoul Zig KMS C ABI.

This package loads `libkms` from:
- `KMS_LIB_PATH` env var (preferred), or
- `VOLTAIRE_LIB_PATH` env var (legacy compatibility), or
- `zig/zig-out/lib` in this monorepo.
