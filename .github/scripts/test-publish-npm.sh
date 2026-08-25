#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
publisher="$repo_root/.github/scripts/publish-npm.sh"
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

make_tarball() {
  local name="$1"
  local package_json="$2"
  local package_dir="$fixture_dir/$name/package"
  mkdir -p "$package_dir"
  printf '%s\n' "$package_json" >"$package_dir/package.json"
  tar -czf "$fixture_dir/$name.tgz" -C "$fixture_dir/$name" package
}

mkdir -p "$fixture_dir/bin"
# The single-quoted variables belong to the generated npm stub, not this test.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'case "${1:-}" in' \
  '  pack) exit 0 ;;' \
  '  view) echo "npm ERR! E404 404 Not Found" >&2; exit 1 ;;' \
  '  publish) printf "%s\n" "$@" >"$PUBLISH_ARGS_FILE" ;;' \
  '  *) exit 2 ;;' \
  'esac' \
  >"$fixture_dir/bin/npm"
chmod +x "$fixture_dir/bin/npm"
export PATH="$fixture_dir/bin:$PATH"
export PUBLISH_ARGS_FILE="$fixture_dir/publish-args.txt"

make_tarball valid '{"name":"@starknetfoundation/krusty-kms-wasm","version":"0.0.0-test"}'
"$publisher" "$fixture_dir/valid.tgz" >/dev/null
grep -Fx -- '--ignore-scripts' "$PUBLISH_ARGS_FILE" >/dev/null
grep -Fx -- '--provenance' "$PUBLISH_ARGS_FILE" >/dev/null

make_tarball scripts '{"name":"@starknetfoundation/krusty-kms-wasm","version":"0.0.0-test","scripts":{}}'
expect_failure "lifecycle scripts" "$publisher" "$fixture_dir/scripts.tgz"

make_tarball wrong-name '{"name":"attacker-package","version":"0.0.0-test"}'
expect_failure "wrong package name" "$publisher" "$fixture_dir/wrong-name.tgz"

expect_failure "missing tarball" "$publisher" "$fixture_dir/missing.tgz"

echo "npm publishing self-tests passed."
