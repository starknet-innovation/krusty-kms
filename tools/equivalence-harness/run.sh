#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cargo build --manifest-path "$ROOT_DIR/tools/rust-oracle/Cargo.toml"
zig build-exe \
  --dep kms_zig \
  -Mmain="$ROOT_DIR/tools/zig-oracle/main.zig" \
  -Mkms_zig="$ROOT_DIR/zig/src/root.zig" \
  -O ReleaseFast \
  -femit-bin="$ROOT_DIR/tools/zig-oracle/zig-oracle"
cargo run --manifest-path "$ROOT_DIR/tools/equivalence-harness/Cargo.toml" -- \
  --rust-bin "$ROOT_DIR/tools/rust-oracle/target/debug/rust-oracle" \
  --zig-bin "$ROOT_DIR/tools/zig-oracle/zig-oracle" \
  --vectors "$ROOT_DIR/fixtures/vectors/parity/core-vectors.json" \
  --mode vectors \
  --artifacts-dir "$ROOT_DIR/tools/equivalence-harness/artifacts" \
  --fail-fast true
