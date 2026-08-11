# Design: reconcile unpublished release versions

Date: 2026-08-11

## Problem

The previous CI policy required every source-changing PR to bump the workspace
version. Several PRs therefore advanced the workspace from `0.5.4` through
`0.9.7`, including dated changelog entries, without creating a release tag or
publishing to crates.io. The next release would have bundled those changes
under `0.9.7` even though the last published version was `0.5.4`.

## Goals

- Publish the accumulated post-`0.5.4` work as one `0.6.0` release.
- Keep all published workspace crates and their internal dependency constraints
  resolvable at the selected version.
- Require a release version bump to begin from the latest published
  `krusty-kms` version, rather than from an unpublished manifest version.
- Preserve immutable tags, including the cancelled, unpublished `v0.9.7` tag.

## Non-goals

- Retagging, deleting, or publishing the cancelled `v0.9.7` attempt.
- Releasing each historical, untagged candidate version separately.
- Changing public APIs beyond the API changes already accumulated after `0.5.4`.

## Design

The release changelog has one `0.6.0` entry containing all substantive notes
that were previously split across untagged `0.6.0`–`0.9.7` headings. The root
workspace version, lockfile, and internal path-dependency requirements are
aligned to `0.6.0`, so every package resolves against its in-tree dependency
version during packaging.

Normal feature and fix PRs no longer have to change the workspace version.
They keep release notes under `Unreleased`. A PR that changes the root version
runs `check-release-version-base.sh`, which retrieves the latest published
`krusty-kms` version from crates.io and permits an ordinary version increase
only when that value equals the PR base version.

The guard has one recovery path for this incident: if the base version is above
crates.io, the proposed version must be strictly below the base and strictly
above the published version. This allows a maintainer to reconcile a cancelled
or otherwise unpublished version bump, but prevents another upward bump from
the unpublished base.

## Invariants

- Every published workspace crate inherits the selected root version.
- Internal publishable-crate requirements accept the selected workspace version.
- A second release version cannot be proposed until the previous workspace
  version is visible on crates.io.
- Git tags are never deleted, moved, or recreated.

## Failure modes

- If crates.io cannot be queried or does not report a version, a release PR
  fails closed; a maintainer retries after the registry is available.
- If a release partially publishes, rerun its existing workflow so the publish
  script skips already-visible crates and continues in dependency order.
- If a version bump starts from an unpublished base, CI rejects it unless it is
  the strictly downward reconciliation described above.
