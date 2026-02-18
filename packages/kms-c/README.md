# @ghoul/kms-c

C ABI distribution package for the Zig KMS core.

## Contents

- `include/kms.h`: Stable public ABI header.

## Build Notes

The header targets libraries produced by:

- `zig build --build-file /Users/theodorepender/Coding/kms/zig/build.zig`

Link against `libkms` from the Zig build output.
