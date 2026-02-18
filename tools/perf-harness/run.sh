#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cargo build -p rust-oracle -p perf-harness --release --manifest-path "$ROOT_DIR/Cargo.toml"
zig build-exe \
  --dep kms_zig \
  -Mmain="$ROOT_DIR/tools/zig-oracle/main.zig" \
  -Mkms_zig="$ROOT_DIR/zig/src/root.zig" \
  -O ReleaseFast \
  -femit-bin="$ROOT_DIR/tools/zig-oracle/zig-oracle-release"

cargo run -p perf-harness --release --manifest-path "$ROOT_DIR/Cargo.toml" -- \
  --rust-bin "$ROOT_DIR/target/release/rust-oracle" \
  --zig-bin "$ROOT_DIR/tools/zig-oracle/zig-oracle-release" \
  --vectors "$ROOT_DIR/fixtures/vectors/parity/core-vectors.json" \
  --out-dir "$ROOT_DIR/tools/perf-harness/results" \
  --samples 5 \
  --warmup 1
