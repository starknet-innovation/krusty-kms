#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cargo build -p rust-oracle -p perf-harness --release --manifest-path "$ROOT_DIR/Cargo.toml"

cargo run -p perf-harness --release --manifest-path "$ROOT_DIR/Cargo.toml" -- \
  --oracle-bin "$ROOT_DIR/target/release/rust-oracle" \
  --vectors "$ROOT_DIR/fixtures/vectors/parity/core-vectors.json" \
  --out-dir "$ROOT_DIR/tools/perf-harness/results" \
  --samples 5 \
  --warmup 1
