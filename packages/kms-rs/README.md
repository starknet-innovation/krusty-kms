# ghoul-kms (Rust)

Rust FFI wrapper crate for the Zig KMS C ABI.

`build.rs` links against `zig/zig-out/lib/libkms` by default.

The crate maps all exported functions from `zig/include/kms.h` to safe Rust wrappers.
