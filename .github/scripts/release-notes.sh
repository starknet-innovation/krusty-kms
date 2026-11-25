#!/usr/bin/env bash
# Print the GitHub Release notes for one version: the body of its
# `## [<version>] - YYYY-MM-DD` CHANGELOG section, with repository-relative
# Markdown links pinned to the release tag so they keep pointing at the
# released files.
#
# Usage: release-notes.sh <version> <tag>
# Env:   CHANGELOG_PATH (default CHANGELOG.md),
#        GITHUB_REPOSITORY (default starknet-innovation/krusty-kms)
set -euo pipefail

version="${1:?usage: release-notes.sh <version> <tag>}"
tag="${2:?usage: release-notes.sh <version> <tag>}"
changelog_path="${CHANGELOG_PATH:-CHANGELOG.md}"
repository="${GITHUB_REPOSITORY:-starknet-innovation/krusty-kms}"

if ! [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::release-notes.sh: '${version}' is not a MAJOR.MINOR.PATCH version" >&2
  exit 1
fi
if ! [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::release-notes.sh: '${tag}' is not a vMAJOR.MINOR.PATCH tag" >&2
  exit 1
fi
if ! [[ "${repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "::error::release-notes.sh: '${repository}' is not an owner/name repository" >&2
  exit 1
fi

# Section body: after the heading, up to the next `## ` heading, without the
# leading and trailing blank lines.
# Blank lines are held back and only printed before a later non-blank line.
body="$(awk -v heading="## [${version}] - " '
  index($0, heading) == 1 { found = 1; next }
  found && /^## / { exit }
  !found { next }
  /^[[:space:]]*$/ { if (started) pending++; next }
  { while (pending > 0) { print ""; pending-- } started = 1; print }
' "${changelog_path}")"

if [[ -z "${body//[[:space:]]/}" ]]; then
  echo "::error::${changelog_path} has no ## [${version}] section with content" >&2
  exit 1
fi

# Pin `](path)` links that are neither absolute URLs (no `:`) nor in-page
# anchors (`#...`) to the tag. `./` prefixes are dropped.
base="https://github.com/${repository}/blob/${tag}/"
printf '%s\n' "${body}" \
  | sed -E "s#\]\((\./)?([^)#:][^):]*)\)#](${base}\2)#g"
