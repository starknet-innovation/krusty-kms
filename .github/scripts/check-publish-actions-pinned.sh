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

# GitHub accepts whitespace around and quotes around YAML mapping keys. This
# scanner recognizes those forms and fails closed if a uses-like key appears in
# syntax it does not understand. Publishing workflows deliberately avoid flow
# mappings and multiline action references so this check has no YAML dependency.
simple_key_pattern='^[[:space:]-]*(uses|"uses"|'"'"'uses'"'"')[[:space:]]*:'
broad_key_pattern='(^|[[:space:]{,?-])(uses|"uses"|'"'"'uses'"'"')[[:space:]]*:'

for file in "${workflow_files[@]}"; do
  if [[ ! -r "$file" ]]; then
    echo "::error file=${file}::publishing workflow cannot be read"
    status=1
    continue
  fi

  broad_lines=""
  if broad_lines="$(LC_ALL=C grep -nE "$broad_key_pattern" "$file")"; then
    :
  else
    grep_status=$?
    if ((grep_status != 1)); then
      echo "::error file=${file}::failed to scan publishing workflow"
      status=1
      continue
    fi
  fi

  matched_lines=""
  if matched_lines="$(LC_ALL=C grep -nE "$simple_key_pattern" "$file")"; then
    :
  else
    grep_status=$?
    if ((grep_status != 1)); then
      echo "::error file=${file}::failed to parse publishing workflow"
      status=1
      continue
    fi
  fi

  if [[ "$broad_lines" != "$matched_lines" ]]; then
    echo "::error file=${file}::publishing workflow contains unsupported uses-key syntax"
    status=1
    continue
  fi

  [[ -z "$matched_lines" ]] && continue
  while IFS=: read -r line source; do
    action_ref="$(sed -E "s/^[[:space:]-]*(uses|\"uses\"|'uses')[[:space:]]*:[[:space:]]*([^[:space:]#]+).*/\2/" <<<"$source")"
    action_ref="${action_ref#\"}"
    action_ref="${action_ref%\"}"
    action_ref="${action_ref#\'}"
    action_ref="${action_ref%\'}"

    if [[ -z "$action_ref" || "$action_ref" == "$source" ]]; then
      echo "::error file=${file},line=${line}::could not parse publishing action reference"
      status=1
      continue
    fi

    if [[ "$action_ref" == ./* ]]; then
      continue
    fi

    if [[ "$action_ref" == docker://* ]]; then
      if [[ ! "$action_ref" =~ ^docker://[^@]+@sha256:[0-9a-fA-F]{64}$ ]]; then
        echo "::error file=${file},line=${line}::publishing docker action must use a sha256 digest: ${action_ref}"
        status=1
      fi
      continue
    fi

    revision="${action_ref##*@}"
    if [[ "$action_ref" != *@* || ! "$revision" =~ ^[0-9a-fA-F]{40}$ ]]; then
      echo "::error file=${file},line=${line}::publishing action must use a full commit SHA: ${action_ref}"
      status=1
    fi
  done <<<"$matched_lines"
done

if ((status != 0)); then
  exit "$status"
fi

echo "Publishing workflow actions are pinned to immutable revisions."
