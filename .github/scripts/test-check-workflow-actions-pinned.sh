#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="$repo_root/.github/scripts/check-workflow-actions-pinned.sh"
checker_rb="$repo_root/.github/scripts/check-workflow-actions-pinned.rb"
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

# Run the checker with its default scope from a fixture repository root.
check_repo() {
  (cd "$1" && ruby "$checker_rb")
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

# Action inputs may carry keys named image/container/uses as plain data; only
# real action references and job/service containers are validated.
printf '%s\n' \
  'jobs:' \
  '  build:' \
  '    runs-on: ubuntu-latest' \
  '    steps:' \
  "      - uses: docker/build-push-action@${full_sha}" \
  '        with:' \
  '          image: alpine:3.20' \
  '          container: registry.example.com/app:latest' \
  '          uses: not-an-action' \
  >"$fixture_dir/inputs.yml"
"$checker" "$fixture_dir/inputs.yml" >/dev/null

# A job named `with` is not an inputs block: its actions are still checked.
printf '%s\n' \
  'jobs:' \
  '  with:' \
  '    runs-on: ubuntu-latest' \
  '    steps:' \
  '      - uses: actions/checkout@v7' \
  >"$fixture_dir/job-named-with.yml"
expect_failure "mutable action in a job named with" "$checker" "$fixture_dir/job-named-with.yml"

# Reusable-workflow inputs under jobs.<job>.with are data, not references.
printf '%s\n' \
  'jobs:' \
  '  call:' \
  "    uses: org/repo/.github/workflows/reusable.yml@${full_sha}" \
  '    with:' \
  '      uses: not-an-action' \
  >"$fixture_dir/reusable-inputs.yml"
"$checker" "$fixture_dir/reusable-inputs.yml" >/dev/null

# `uses` keys outside the two action-reference positions are data.
printf '%s\n' \
  'env:' \
  '  uses: top-level-data' \
  'jobs:' \
  '  build:' \
  '    runs-on: ubuntu-latest' \
  '    env:' \
  '      uses: plain-data' \
  '    steps:' \
  "      - uses: actions/checkout@${full_sha}" \
  '        env:' \
  '          uses: step-data' \
  >"$fixture_dir/env-data.yml"
"$checker" "$fixture_dir/env-data.yml" >/dev/null

printf '%s\n' 'jobs:' '  test:' '    steps:' '      - uses: actions/checkout@v7' >"$fixture_dir/mutable.yml"
expect_failure "mutable GitHub action" "$checker" "$fixture_dir/mutable.yml"

printf '%s\n' 'jobs:' '  test:' '    steps:' '      - uses: docker://alpine:latest' >"$fixture_dir/docker-tag.yml"
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

printf '%s\n' 'jobs:' '  test:' '    steps:' "      - uses: './local-action'" >"$fixture_dir/local.yml"
expect_failure "repository-local action" "$checker" "$fixture_dir/local.yml"

printf '%s\n' 'jobs:' '  test:' '    steps:' '      - ? uses' '        : actions/checkout@v7' >"$fixture_dir/explicit-key.yml"
expect_failure "mutable action under an explicit YAML key" "$checker" "$fixture_dir/explicit-key.yml"

printf '%s\n' \
  'pinned: &pinned' \
  "  uses: actions/checkout@${full_sha}" \
  'jobs:' \
  '  test:' \
  '    steps:' \
  '      - *pinned' \
  >"$fixture_dir/alias.yml"
expect_failure "YAML aliases" "$checker" "$fixture_dir/alias.yml"

expect_failure "unreadable workflow" "$checker" "$fixture_dir/missing.yml"

# The default scope must cover every workflow, not only the publishing ones:
# a tag-pinned action in an ordinary CI workflow has to fail the repo check.
repo_workflows="$fixture_dir/repo/.github/workflows"
mkdir -p "$repo_workflows"
printf '%s\n' 'jobs:' '  publish:' '    steps:' "      - uses: actions/checkout@${full_sha}" \
  >"$repo_workflows/publish.yml"
printf '%s\n' 'jobs:' '  test:' '    steps:' '      - uses: actions/checkout@v7' \
  >"$repo_workflows/rust.yml"
expect_failure "mutable action in a non-publishing workflow" check_repo "$fixture_dir/repo"

printf '%s\n' 'jobs:' '  test:' '    steps:' "      - uses: actions/checkout@${full_sha}" \
  >"$repo_workflows/rust.yml"
check_repo "$fixture_dir/repo" >/dev/null

mkdir -p "$fixture_dir/empty/.github/workflows"
expect_failure "repository without workflows" check_repo "$fixture_dir/empty"

(cd "$fixture_dir" && "$checker" >/dev/null)

echo "Workflow action pinning self-tests passed."
