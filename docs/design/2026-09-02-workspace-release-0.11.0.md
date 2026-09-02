# Workspace release 0.11.0

## Context

The workspace publishes eight crates that inherit a common version and depend on
one another through explicit pre-1.0 version requirements. After the `0.10.0`
release, merged API additions and security hardening require a new published
version.

## Decision

Release every publishable crate as `0.11.0` in one atomic workspace change.
Update each internal path dependency requirement to `0.11.0`, refresh the lockfile,
and keep the release notes in the dated changelog entry.

## Consequences

Downstream Cargo resolution cannot combine a `0.11.0` crate with an internal
`0.10.0` sibling. The release commit contains metadata and release notes only;
the user-visible behavior is the already-merged work described in `CHANGELOG.md`.
