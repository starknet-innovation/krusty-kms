#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="$repo_root/.github/scripts/check-publish-actions-pinned.sh"
fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT

expect_failure() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "self-test failed: $description unexpectedly passed" >&2
    exit 1
  fi
}

full_sha="0123456789abcdef0123456789abcdef01234567"
full_digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

printf '%s\n' \
  'jobs:' \
  '  test:' \
  '    steps:' \
  "      - uses : \"actions/checkout@${full_sha}\"" \
  "      - 'uses' : './local-action'" \
  "      - \"uses\": docker://alpine@sha256:${full_digest}" \
  >"$fixture_dir/valid.yml"
"$checker" "$fixture_dir/valid.yml" >/dev/null

printf '%s\n' 'steps:' '  - uses: actions/checkout@v7' >"$fixture_dir/mutable.yml"
expect_failure "mutable GitHub action" "$checker" "$fixture_dir/mutable.yml"

printf '%s\n' 'steps:' '  - uses: docker://alpine:latest' >"$fixture_dir/docker-tag.yml"
expect_failure "mutable Docker action" "$checker" "$fixture_dir/docker-tag.yml"

printf '%s\n' \
  'steps:' \
  "  - { \"uses\": actions/checkout@${full_sha} }" \
  >"$fixture_dir/unsupported.yml"
expect_failure "unsupported YAML must fail closed" "$checker" "$fixture_dir/unsupported.yml"

expect_failure "unreadable workflow" "$checker" "$fixture_dir/missing.yml"

echo "Publishing action pinning self-tests passed."
