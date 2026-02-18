#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ZIG_BIN="${ZIG_BIN:-$ROOT_DIR/tools/zig-oracle/zig-oracle-release}"
REQ='{"op":"she.range_prove_verify","inputs":{"value":"7","bit_size":8,"prefix":"0x2a"},"rng":{"mode":"deterministic","seed_hex":"0x5555555555555555555555555555555555555555555555555555555555555555","stream":"she-range"}}'

if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "macOS profile hint:"
  echo "  sample $(basename \"$ZIG_BIN\") 5 1000 -file zig.sample.txt"
else
  echo "Linux profile hint:"
  echo "  perf record -F 999 -g -- $ZIG_BIN <<< '$REQ'"
  echo "  perf report"
fi

echo "Raw execution sample:"
printf '%s' "$REQ" | "$ZIG_BIN" >/dev/null
