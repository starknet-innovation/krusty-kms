#!/usr/bin/env bash
# Canonical local validation entrypoint. Keep the commands here aligned with
# .github/workflows/rust.yml so contributors and agents exercise the same paths.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

usage() {
  cat <<'EOF'
Usage: bash tools/check.sh <mode>

Modes:
  quick       Formatting plus fast maintainability guardrails
  rust        Formatting, Clippy, examples, and native Rust tests
  wasm        WASM boundary tests and generated TypeScript declaration check
  all         rust + guardrails + wasm (standard pre-handoff check)
  fmt         Check Rust formatting
  lint        Run the workspace and NATS-feature Clippy checks
  lint-complexity
              Run the workspace and NATS-feature Clippy cognitive-complexity checks
  examples    Check the maintained examples
  test        Run native workspace and NATS-feature tests
  guardrails  Run fast local maintainability fitness checks
  memory      Inspect native + WASM mnemonic memory with a no-scrub control
  memory-native
              Inspect optimized native mnemonic memory
  memory-wasm Inspect optimized WASM mnemonic memory under Node
  help        Show this message

The WASM crate is deliberately excluded from native cargo tests and is tested
only through the wasm mode.
EOF
}

run() {
  printf '\n==> %s\n' "$*"
  "$@"
}

check_fmt() {
  run cargo fmt --all -- --check
}

check_lint_with() {
  local lint_args=("$@")
  run cargo clippy --workspace --all-targets --locked -- -D warnings "${lint_args[@]}"
  run cargo clippy -p krusty-kms-client --all-targets --features nats --locked -- -D warnings "${lint_args[@]}"
}

check_lint() {
  check_lint_with
}

check_cognitive_lint() {
  check_lint_with -D clippy::cognitive_complexity
}

check_examples() {
  run cargo check -p krusty-kms --examples --locked
  run cargo check -p krusty-kms-sdk --examples --locked
}

check_tests() {
  run cargo test --workspace --locked --exclude krusty-kms-wasm
  run cargo test -p krusty-kms-client --locked --features nats
}

check_guardrails() {
  if ((BASH_VERSINFO[0] < 4)); then
    echo "guardrails need bash >= 4 (e.g. brew install bash)" >&2
    exit 1
  fi

  local scripts=(
    .github/scripts/check-file-size-ratchet.sh
    .github/scripts/check-dependency-layers.sh
    .github/scripts/check-unsafe-allowlist.sh
    .github/scripts/check-secret-hygiene.sh
    .github/scripts/check-ffi-surface.sh
    .github/scripts/check-wasm-exports.sh
  )

  local script
  for script in "${scripts[@]}"; do
    run bash "$script"
  done

  run python3 .github/scripts/check-code-complexity.py
}

# The `wasm-bindgen` version Cargo.lock resolves; wasm-pack needs a CLI of
# exactly that version.
locked_wasm_bindgen_version() {
  awk '
    /^name = "wasm-bindgen"$/ { want = 1; next }
    want && /^version = / { gsub(/^version = "|"$/, ""); print; exit }
  ' Cargo.lock
}

check_wasm() {
  # With a wasm-bindgen CLI of the locked version on PATH (built from
  # crates.io by .github/scripts/install-wasm-bindgen-cli.sh), forbid
  # wasm-pack from downloading any tool. CI always installs it first;
  # locally, fall back to wasm-pack's own download so the mode keeps working
  # out of the box, including right after a lockfile bump.
  local wanted installed=""
  wanted="$(locked_wasm_bindgen_version)"
  if command -v wasm-bindgen >/dev/null 2>&1; then
    installed="$(wasm-bindgen --version 2>/dev/null | awk '{ print $2 }')"
  fi
  if [[ -n "$installed" && "$installed" == "$wanted" ]]; then
    run wasm-pack test --node --mode no-install crates/wasm
    run wasm-pack build crates/wasm --target web --out-dir pkg --mode no-install
  elif [[ -n "${CI:-}" ]]; then
    echo "wasm-bindgen ${wanted} is not on PATH (found '${installed:-none}');" >&2
    echo "run bash .github/scripts/install-wasm-bindgen-cli.sh first" >&2
    exit 1
  else
    echo "note: wasm-bindgen ${wanted} is not on PATH (found '${installed:-none}'), so" >&2
    echo "      wasm-pack will download a prebuilt one; run" >&2
    echo "      bash .github/scripts/install-wasm-bindgen-cli.sh to build it from crates.io" >&2
    run wasm-pack test --node crates/wasm
    run wasm-pack build crates/wasm --target web --out-dir pkg
  fi
  run npm ci --prefix cross-tests
  run npm run check:wasm-types --prefix cross-tests
}

check_rust() {
  check_fmt
  check_lint
  check_examples
  check_tests
}

check_memory() {
  local backend="$1"
  local args=(--backend "$backend" --toolchain "${RUSTUP_TOOLCHAIN:-stable}")
  if [[ -n "${KMS_MEMORY_REPORT_DIR:-}" ]]; then
    args+=(--report-dir "$KMS_MEMORY_REPORT_DIR")
  fi
  run python3 tools/memory-inspection/run.py "${args[@]}"
}

mode="${1:-help}"
if (($# > 1)); then
  usage >&2
  exit 2
fi

case "$mode" in
  quick)
    check_fmt
    check_guardrails
    ;;
  rust)
    check_rust
    ;;
  wasm)
    check_wasm
    ;;
  all)
    check_rust
    check_guardrails
    check_wasm
    ;;
  fmt)
    check_fmt
    ;;
  lint)
    check_lint
    ;;
  lint-complexity)
    check_cognitive_lint
    ;;
  examples)
    check_examples
    ;;
  test)
    check_tests
    ;;
  guardrails)
    check_guardrails
    ;;
  memory)
    check_memory all
    ;;
  memory-native)
    check_memory native
    ;;
  memory-wasm)
    check_memory wasm
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "unknown mode: $mode" >&2
    usage >&2
    exit 2
    ;;
esac
