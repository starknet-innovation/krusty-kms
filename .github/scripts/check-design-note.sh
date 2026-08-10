#!/usr/bin/env bash
# Require a design note when public API surface, production dependencies, or
# guardrail baselines change.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

base_ref="${GUARDRAILS_BASE_REF:-}"
pr_body="${PR_BODY:-}"
fail_closed="${GUARDRAILS_FAIL_CLOSED:-}"

if [[ -z "$base_ref" ]]; then
  if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    base_ref="origin/${GITHUB_BASE_REF}"
  else
    base_ref="origin/main"
  fi
fi

if [[ -z "$fail_closed" && -n "${GITHUB_BASE_REF:-}" ]]; then
  fail_closed=1
fi

if ! git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
  git fetch --no-tags origin "${GITHUB_BASE_REF:-main}"
fi
if ! git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
  if [[ "$fail_closed" == "1" ]]; then
    echo "::error::cannot resolve base ref $base_ref; design-note check fails closed"
    exit 1
  fi
  echo "::warning::cannot resolve base ref $base_ref; skipping design-note check"
  exit 0
fi

mapfile -t changed < <(git diff --name-only "$base_ref"...HEAD)

needs_note=0
needs_design_file=0
reasons=()

is_src_rs() {
  case "$1" in
    crates/*/src/*.rs|crates/*/src/*/*.rs|crates/*/src/*/*/*.rs) return 0 ;;
    *) return 1 ;;
  esac
}

for f in "${changed[@]}"; do
  case "$f" in
    crates/experimental/*) continue ;;
  esac

  if is_src_rs "$f"; then
    if git diff "$base_ref"...HEAD -- "$f" | grep -E '^\+\s*pub(\s|\()' >/dev/null; then
      needs_note=1
      reasons+=("new/changed pub items in $f")
    fi
  fi

  case "$f" in
    crates/*/Cargo.toml)
      if git diff "$base_ref"...HEAD -- "$f" | grep -E '^\+[a-zA-Z0-9_-]+\s*=' >/dev/null; then
        needs_note=1
        reasons+=("dependency manifest changed: $f")
      fi
      ;;
    .github/guardrails/file-size-baseline.json|\
    .github/guardrails/wasm-exports.txt|\
    .github/guardrails/ffi-kms.h.snapshot)
      needs_note=1
      needs_design_file=1
      reasons+=("guardrail baseline/surface changed: $f")
      ;;
  esac
done

if (( needs_note == 0 )); then
  echo "design-note check: no triggering public-surface changes"
  exit 0
fi

has_design_file=0
for f in "${changed[@]}"; do
  if [[ "$f" == docs/design/* ]]; then
    has_design_file=1
  fi
done

has_note=$has_design_file
if grep -qiE '^##[[:space:]]*Design\b|docs/design/' <<<"$pr_body"; then
  has_note=1
fi

if (( needs_design_file == 1 )) && (( has_design_file == 0 )); then
  echo "::error::security/boundary baseline changes require a docs/design/*.md file (PR body alone is not enough)"
  for r in "${reasons[@]}"; do
    echo "  - $r"
  done
  exit 1
fi

if (( has_note == 0 )); then
  echo "::error::public API / dependency / surface-snapshot change requires a design note"
  for r in "${reasons[@]}"; do
    echo "  - $r"
  done
  echo "Add docs/design/YYYY-MM-DD-slug.md or a ## Design section in the PR body."
  exit 1
fi

echo "design-note check ok"
printf '  triggered by:\n'
for r in "${reasons[@]}"; do
  echo "  - $r"
done
