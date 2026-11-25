#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
notes="$repo_root/.github/scripts/release-notes.sh"
fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT

fail() {
  echo "self-test failed: $1" >&2
  exit 1
}

expect_failure() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    fail "$description unexpectedly passed"
  fi
}

cat >"$fixture_dir/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

- Not released.

## [2.0.0] - 2026-01-02

Read the [guide](docs/migration-2.0.md) and [notes](./docs/notes.md).
Keep [upstream](https://example.com/a) and [anchor](#added) links.
See [a section](docs/a.md#sec), [titled](docs/t.md "T"), [rooted](/docs/r.md)
and ![diagram](docs/d.png).

### Added

- New `thing`.


## [1.0.0] - 2026-01-01

- Old.
EOF

export CHANGELOG_PATH="$fixture_dir/CHANGELOG.md"
export GITHUB_REPOSITORY="owner/repo"

actual="$(bash "$notes" 2.0.0 v2.0.0)"
expected="$(cat <<'EOF'
Read the [guide](https://github.com/owner/repo/blob/v2.0.0/docs/migration-2.0.md) and [notes](https://github.com/owner/repo/blob/v2.0.0/docs/notes.md).
Keep [upstream](https://example.com/a) and [anchor](#added) links.
See [a section](https://github.com/owner/repo/blob/v2.0.0/docs/a.md#sec), [titled](https://github.com/owner/repo/blob/v2.0.0/docs/t.md "T"), [rooted](https://github.com/owner/repo/blob/v2.0.0/docs/r.md)
and ![diagram](https://github.com/owner/repo/raw/v2.0.0/docs/d.png).

### Added

- New `thing`.
EOF
)"
[[ "$actual" == "$expected" ]] || fail "2.0.0 notes differ:
$actual"

[[ "$(bash "$notes" 1.0.0 v1.0.0)" == "- Old." ]] || fail "last section not extracted"

expect_failure "a missing section" bash "$notes" 3.0.0 v3.0.0
expect_failure "a non-semver version" bash "$notes" 2.0 v2.0.0
expect_failure "a tag without v" bash "$notes" 2.0.0 2.0.0
GITHUB_REPOSITORY='owner/repo#x' expect_failure "an odd repository" bash "$notes" 2.0.0 v2.0.0

echo "Release notes self-tests passed."
