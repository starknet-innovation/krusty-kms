#!/usr/bin/env bash
set -euo pipefail

base_ref="${1:?usage: check-release-version-base.sh <base-ref>}"
crate_name="krusty-kms"
user_agent="krusty-kms-ci (https://github.com/starknet-innovation/krusty-kms)"

workspace_version_at() {
  local ref="$1"
  local version

  version="$(git show "${ref}:Cargo.toml" \
    | sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)"/\1/p' \
    | head -n1)"

  if [[ -z "${version}" ]]; then
    echo "::error::could not read the workspace version from ${ref}:Cargo.toml" >&2
    exit 1
  fi

  printf '%s\n' "${version}"
}

workspace_version() {
  local version

  version="$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)"/\1/p' Cargo.toml | head -n1)"
  if [[ -z "${version}" ]]; then
    echo "::error::could not read the workspace version from Cargo.toml" >&2
    exit 1
  fi

  printf '%s\n' "${version}"
}

compare_versions() {
  local left="$1"
  local right="$2"

  python3 - "${left}" "${right}" <<'PY'
import re
import sys


def parse(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value)
    if not match:
        raise ValueError(f"{value!r} is not a numeric MAJOR.MINOR.PATCH release version")
    return tuple(map(int, match.groups()))


try:
    left = parse(sys.argv[1])
    right = parse(sys.argv[2])
except ValueError as error:
    print(f"::error::{error}", file=sys.stderr)
    sys.exit(2)

print((left > right) - (left < right))
PY
}

base_version="$(workspace_version_at "${base_ref}")"
head_version="$(workspace_version)"
published_version="${PUBLISHED_WORKSPACE_VERSION:-}"

if [[ -z "${published_version}" ]]; then
  published_version="$(curl --fail --silent --show-error --retry 3 --retry-all-errors \
    -A "${user_agent}" "https://crates.io/api/v1/crates/${crate_name}" \
    | jq --exit-status --raw-output '.crate.max_version')"
fi

if [[ -z "${published_version}" || "${published_version}" == "null" ]]; then
  echo "::error::could not determine the latest published ${crate_name} version" >&2
  exit 1
fi

base_matches_published="$(compare_versions "${base_version}" "${published_version}")"
head_matches_base="$(compare_versions "${head_version}" "${base_version}")"

if [[ "${base_matches_published}" == "0" ]]; then
  if [[ "${head_matches_base}" != "1" ]]; then
    echo "::error::release version ${head_version} must be greater than ${base_version}" >&2
    exit 1
  fi

  echo "release version ${head_version} starts from published ${crate_name}@${published_version}"
  exit 0
fi

# This branch handles a recovery after an untagged/cancelled version bump. It must
# move the manifest back toward the next release after crates.io, never advance it.
head_matches_published="$(compare_versions "${head_version}" "${published_version}")"
if [[ "${base_matches_published}" == "1" \
  && "${head_matches_base}" == "-1" \
  && "${head_matches_published}" == "1" ]]; then
  echo "::warning::reconciling unpublished workspace version ${base_version} to ${head_version}; crates.io is at ${published_version}"
  exit 0
fi

echo "::error::workspace base version ${base_version} does not match the latest published ${crate_name}@${published_version}; publish or reconcile it before opening another release version bump" >&2
exit 1
