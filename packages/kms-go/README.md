# ghoul-kms-go

Go wrapper for `libkms` via cgo.

The package exposes the full `kms.h` API surface with idiomatic Go types.

Expected native library path:
- `zig/zig-out/lib` (via cgo linker flags in `internal/ffi/ffi.go`)
