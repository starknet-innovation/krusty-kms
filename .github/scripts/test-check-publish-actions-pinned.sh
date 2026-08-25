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
  "      - \"uses\": docker://alpine@sha256:${full_digest}" \
  "      - { \"uses\": actions/cache@${full_sha} }" \
  '      - ? uses' \
  "        : actions/setup-node@${full_sha}" \
  "    container: ghcr.io/example/release@sha256:${full_digest}" \
  '    services:' \
  '      database:' \
  "        image: postgres@sha256:${full_digest}" \
  >"$fixture_dir/valid.yml"
"$checker" "$fixture_dir/valid.yml" >/dev/null

printf '%s\n' 'steps:' '  - uses: actions/checkout@v7' >"$fixture_dir/mutable.yml"
expect_failure "mutable GitHub action" "$checker" "$fixture_dir/mutable.yml"

printf '%s\n' 'steps:' '  - uses: docker://alpine:latest' >"$fixture_dir/docker-tag.yml"
expect_failure "mutable Docker action" "$checker" "$fixture_dir/docker-tag.yml"

printf '%s\n' 'jobs:' '  publish:' '    container: alpine:latest' >"$fixture_dir/container.yml"
expect_failure "mutable job container" "$checker" "$fixture_dir/container.yml"

printf '%s\n' \
  'jobs:' \
  '  publish:' \
  '    services:' \
  '      database:' \
  '        image: postgres:latest' \
  >"$fixture_dir/service.yml"
expect_failure "mutable service container" "$checker" "$fixture_dir/service.yml"

printf '%s\n' 'steps:' "  - uses: './local-action'" >"$fixture_dir/local.yml"
expect_failure "repository-local action" "$checker" "$fixture_dir/local.yml"

printf '%s\n' 'steps:' '  - ? uses' '    : actions/checkout@v7' >"$fixture_dir/explicit-key.yml"
expect_failure "mutable action under an explicit YAML key" "$checker" "$fixture_dir/explicit-key.yml"

printf '%s\n' \
  'pinned: &pinned' \
  "  uses: actions/checkout@${full_sha}" \
  'steps:' \
  '  - *pinned' \
  >"$fixture_dir/alias.yml"
expect_failure "YAML aliases" "$checker" "$fixture_dir/alias.yml"

expect_failure "unreadable workflow" "$checker" "$fixture_dir/missing.yml"

(cd "$fixture_dir" && "$checker" >/dev/null)

echo "Publishing action pinning self-tests passed."
