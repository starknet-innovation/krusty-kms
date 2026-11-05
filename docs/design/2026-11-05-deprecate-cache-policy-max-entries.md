# Deprecate `CachePolicy::max_entries`

Date: 2026-11-05. Status: accepted.

## Problem

`krusty_kms_domain::CachePolicy` carries `max_entries`. The gateway once
sized the shared snapshot cache from it. One client could then flush every
other client's cache by sending a small value, so eviction moved to a
process-global ceiling and the per-request value has been ignored since.
Callers still had to supply it, though, and both `CachePolicy::new` and the
gateway rejected `0`. The only sign that it was ignored was doc text, and the
1.0.0 cleanup of `#[deprecated]` APIs (`2026-11-05-release-1.0.0.md`) could
not catch it. The field is part of the published 1.x API and of the oracle
v1.0 wire format, so it cannot be removed before 2.0.0.

## Decision

Phase it out within 1.x with no breaking change:

- Mark the field and `CachePolicy::new` `#[deprecated(since = "1.1.0")]`, so
  Rust callers get a compiler warning that points at the replacement.
- Add `CachePolicy::with_ttl(ttl_ms, stale_while_revalidate_ms)`, which takes
  only the meaningful arguments and validates `ttl_ms > 0` as before.
- Add `#[serde(default)]` on the field: wire clients may omit it, and it then
  becomes `DEFAULT_MAX_ENTRIES`.
- Drop the `> 0` checks in `CachePolicy::new` and the gateway. Validating a
  value nobody reads only forced callers to invent one.

`DEFAULT_MAX_ENTRIES` is `1`, not `0`, and the field is still serialized. A
1.1 client talking to a 1.0 gateway therefore sends `max_entries: 1`, which
the old gateway accepts. Skipping the field on serialization, or defaulting
to `0`, would break that pairing.

## Compatibility

- Rust: additive (`with_ttl`, the constant) plus deprecations, so this is a
  minor release (1.1.0). Struct-literal construction still compiles, with a
  deprecation warning. `cargo-semver-checks` classifies the two deprecations
  as minor-level (`struct_field_marked_deprecated`,
  `type_method_marked_deprecated`), not breaking.
- Wire: every oracle v1.0 message stays valid in both directions, so the
  protocol version stays 1.0. The only new behaviour is that messages without
  `max_entries` are accepted, as are messages with `max_entries: 0`.

## Semver guardrail

This is the first feature PR since 1.0.0 to make a minor-level API change.
`check-semver.sh` ran `check-release` with no release type, so it compared
the branch as if it shipped at the unchanged workspace version 1.0.0. It
therefore failed with "requires new minor version" (exit 100). Feature PRs
never bump the version; the release PR does. Before 1.0 this never came up,
because the minor-level lints map to a patch bump at 0.y and no feature PR
had tripped them.

The script now passes `--release-type minor`. Additions and deprecations
pass, and breaking changes still fail, which is what the guardrail is for
from 1.0.0 on. Choosing between a minor and a patch release stays with the
release PR, which reads `## [Unreleased]`: an `Added` or `Deprecated`
section means a minor release.

## Removal

In 2.0.0, remove the field, rename `with_ttl` to `new` (or keep both), and
bump the oracle protocol to a version that no longer carries the field.
