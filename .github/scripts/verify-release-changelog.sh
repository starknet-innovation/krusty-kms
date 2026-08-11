#!/usr/bin/env bash
set -euo pipefail

changelog_path="${CHANGELOG_PATH:-CHANGELOG.md}"
version="$(cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "krusty-kms") | .version')"

if [[ ! -f "${changelog_path}" ]]; then
  echo "::error::${changelog_path} is required for every crates.io release"
  exit 1
fi

heading_line="$(grep -nF "## [${version}] - " "${changelog_path}" | cut -d: -f1 | head -n1 || true)"
if [[ -z "${heading_line}" ]]; then
  echo "::error::${changelog_path} needs a ## [${version}] - YYYY-MM-DD entry"
  exit 1
fi

heading="$(sed -n "${heading_line}p" "${changelog_path}")"
if ! [[ "${heading}" =~ ^##\ \[${version}\]\ -\ [0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "::error::changelog entry for ${version} must use ## [${version}] - YYYY-MM-DD"
  exit 1
fi

if ! awk -v start="${heading_line}" '
  NR > start && /^## / { exit }
  NR > start && /^- / { found = 1 }
  END { exit(found ? 0 : 1) }
' "${changelog_path}"; then
  echo "::error::changelog entry for ${version} needs at least one release-note bullet"
  exit 1
fi
