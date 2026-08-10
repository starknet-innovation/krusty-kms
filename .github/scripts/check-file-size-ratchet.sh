#!/usr/bin/env bash
# Fail if oversized files grow past their baseline, or if a new file exceeds
# the hard limit for new sources (see CONTRIBUTING.md).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
baseline_path="${FILE_SIZE_BASELINE:-$root/.github/guardrails/file-size-baseline.json}"
export PYTHONPATH="$root/.github/scripts${PYTHONPATH:+:$PYTHONPATH}"

base_ref="${GUARDRAILS_BASE_REF:-}"
if [[ -z "$base_ref" ]]; then
  if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    base_ref="origin/${GITHUB_BASE_REF}"
  else
    base_ref="origin/main"
  fi
fi

if ! git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
  git fetch --no-tags origin "${GITHUB_BASE_REF:-main}" || true
fi

if [[ ! -f "$baseline_path" ]]; then
  echo "::error::missing file-size baseline at $baseline_path"
  exit 1
fi

python3 - "$baseline_path" "$root" "$base_ref" <<'PY'
import sys
from pathlib import Path

from lib.surfaces import run_file_size_ratchet_check

baseline_path = Path(sys.argv[1])
root = Path(sys.argv[2])
base_ref = sys.argv[3]
sys.exit(
    run_file_size_ratchet_check(
        baseline_path,
        root,
        base_ref=base_ref if base_ref else None,
    )
)
PY
