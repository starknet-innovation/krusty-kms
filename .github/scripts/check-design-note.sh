#!/usr/bin/env bash
# Require a design note when public API surface, production dependencies, or
# guardrail baselines change.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
export PYTHONPATH="$root/.github/scripts${PYTHONPATH:+:$PYTHONPATH}"

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

# Root Cargo.toml centralizes production deps under [workspace.dependencies].
workspace_dep_entries() {
  python3 - "$1" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
_DEP_KEY = re.compile(r"^([a-zA-Z0-9_.-]+)\s*=")


def _normalize_body(body: str) -> str:
    lines = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return "\n".join(lines)


def workspace_dep_entries(cargo_text: str) -> list[str]:
    entries: list[str] = []
    for section in re.split(r"\n(?=\[)", cargo_text):
        if not section.strip():
            continue
        header = section.split("\n", 1)[0].strip()
        if header == "[workspace.dependencies]":
            for line in section.splitlines()[1:]:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if _DEP_KEY.match(stripped):
                    entries.append(stripped)
        elif header.startswith("[workspace.dependencies."):
            body = section.split("\n", 1)[1] if "\n" in section else ""
            norm = _normalize_body(body)
            entries.append(f"{header}\n{norm}" if norm else header)
    return entries


for entry in workspace_dep_entries(text):
    print(entry)
PY
}

root_cargo_workspace_deps_changed() {
  local base_file
  base_file="$(mktemp)"
  # shellcheck disable=SC2064
  trap 'rm -f "$base_file"' RETURN

  if ! git show "$base_ref:Cargo.toml" >"$base_file" 2>/dev/null; then
    workspace_dep_entries Cargo.toml | grep -q .
    return $?
  fi

  ! diff -q \
    <(workspace_dep_entries "$base_file" | LC_ALL=C sort) \
    <(workspace_dep_entries Cargo.toml | LC_ALL=C sort) \
    >/dev/null 2>&1
}

crate_production_dep_entries() {
  python3 - "$1" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
_DEP_KEY = re.compile(r"^([a-zA-Z0-9_-]+)\s*=")
_DEP_TABLE = re.compile(r"^\[(?:.*\.)?dependencies\.([a-zA-Z0-9_-]+)\]")


def _is_production_dep_section(header: str) -> bool:
    return (
        header == "[dependencies]"
        or header.startswith("[dependencies.")
        or ".dependencies]" in header
        or re.match(r"^\[target\..+\.dependencies\]$", header) is not None
    )


def _normalize_body(body: str) -> str:
    lines = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return "\n".join(lines)


def production_dep_entries(text: str) -> list[str]:
    entries: list[str] = []
    for section in re.split(r"\n(?=\[)", text):
        if not section.strip():
            continue
        header = section.split("\n", 1)[0].strip()
        if "dev-dependencies" in header or "build-dependencies" in header:
            continue
        table = _DEP_TABLE.match(header)
        if table:
            body = section.split("\n", 1)[1] if "\n" in section else ""
            norm = _normalize_body(body)
            entries.append(f"{header}\n{norm}" if norm else header)
            continue
        if not _is_production_dep_section(header):
            continue
        for line in section.splitlines()[1:]:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _DEP_KEY.match(stripped):
                entries.append(stripped)
    return sorted(entries)


for entry in production_dep_entries(text):
    print(entry)
PY
}

crate_cargo_production_deps_changed() {
  local f="$1"
  local base_file
  base_file="$(mktemp)"
  # shellcheck disable=SC2064
  trap 'rm -f "$base_file"' RETURN

  if ! git show "$base_ref:$f" >"$base_file" 2>/dev/null; then
    crate_production_dep_entries "$f" | grep -q .
    return $?
  fi

  ! diff -q \
    <(crate_production_dep_entries "$base_file" | LC_ALL=C sort) \
    <(crate_production_dep_entries "$f" | LC_ALL=C sort) \
    >/dev/null 2>&1
}

for f in "${changed[@]}"; do
  case "$f" in
    crates/experimental/*) continue ;;
  esac

  if is_src_rs "$f"; then
    if git diff "$base_ref"...HEAD -- "$f" | grep -E '^[+-]\s*pub\s' >/dev/null; then
      needs_note=1
      reasons+=("new/changed/removed pub items in $f")
    fi
  fi

  case "$f" in
    Cargo.toml)
      if root_cargo_workspace_deps_changed; then
        needs_note=1
        reasons+=("workspace dependency manifest changed: Cargo.toml [workspace.dependencies]")
      fi
      ;;
    crates/*/Cargo.toml)
      if crate_cargo_production_deps_changed "$f"; then
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
