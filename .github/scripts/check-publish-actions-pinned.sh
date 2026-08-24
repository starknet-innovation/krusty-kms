#!/usr/bin/env bash
# Require content-addressed actions in workflows that can publish packages.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

status=0
if (($# > 0)); then
  workflow_files=("$@")
else
  workflow_files=(
    .github/workflows/publish.yml
    .github/workflows/publish-npm.yml
  )
fi

while IFS=: read -r file line source; do
  action_ref="$(sed -E 's/^[[:space:]-]*uses:[[:space:]]*([^[:space:]#]+).*/\1/' <<<"$source")"

  case "$action_ref" in
    ./* | docker://*)
      continue
      ;;
  esac

  revision="${action_ref##*@}"
  if [[ "$action_ref" != *@* || ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
    echo "::error file=${file},line=${line}::publishing action must use a full commit SHA: ${action_ref}"
    status=1
  fi
done < <(rg --line-number --no-heading --with-filename '^[[:space:]-]*uses:[[:space:]]*' \
  "${workflow_files[@]}")

if ((status != 0)); then
  exit "$status"
fi

echo "Publishing workflow actions are pinned to full commit SHAs."
