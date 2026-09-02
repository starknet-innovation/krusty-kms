# crates.io release playbook

This is the required process for publishing the Rust crates in this workspace. It is
for maintainers and automated agents. It does not cover the WASM npm package; that
package is released by [`.github/workflows/publish-npm.yml`](../.github/workflows/publish-npm.yml).

## Release contract

- The only publishing path is [`.github/workflows/publish.yml`](../.github/workflows/publish.yml).
  Do **not** run `cargo publish` locally or add a long-lived crates.io token to GitHub
  or the local environment.
- The workflow obtains a short-lived crates.io token using GitHub Actions OIDC, publishes
  through it, and revokes the token when the job ends.
- The workflow runs only when a `v*` tag is pushed. The tag must be named
  `v<workspace-version>` and must point to a commit reachable from `main`.
- The protected GitHub `crates-io` environment requires approval from its configured
  reviewer before the workflow can obtain a publishing token.
- Every release needs a dated `CHANGELOG.md` entry named `## [<workspace-version>] -
  YYYY-MM-DD` with at least one release-note bullet. CI checks it on a version-bump PR
  and the publishing workflow checks it again before authentication.
- Normal feature and fix PRs must not bump the root workspace version. Keep their
  notes under `## [Unreleased]`; create the dated entry and bump the version only in a
  focused release PR. CI compares the release PR's base version with the latest
  published `krusty-kms` version on crates.io, so a second release bump cannot merge
  while the previous version is still unpublished.
- Release tags are immutable. Never delete, move, recreate, or force-push one.

The workflow publishes these crates in dependency order:

1. `krusty-kms-common`
2. `krusty-kms-wallet-api`
3. `krusty-kms-domain`
4. `krusty-kms-crypto`
5. `krusty-kms`
6. `krusty-kms-sdk`
7. `krusty-kms-client`
8. `krusty-kms-gateway`

Before every release, confirm that every crate above has a crates.io trusted publisher
configured for this repository, the `publish.yml` workflow, and the `crates-io`
environment. If the configuration does not match, stop and correct it in crates.io;
do not fall back to an API token.

## Repository protection

Two GitHub-side controls back the workflow's own checks. Both are configured by a
repository administrator; the workflow verifies the first at runtime and fails before
requesting a crates.io token if it is missing.

### `crates-io` environment

The `publish` job runs in the `crates-io` environment and requires:

- at least one **required reviewer**, with *prevent self-review* enabled so the tag
  pusher cannot approve their own release, and *allow administrators to bypass*
  disabled — the workflow checks all three;
- **deployment branches and tags** set to *Selected branches and tags* with exactly
  one rule: a **tag** pattern `v*`. Releases are tag-triggered, so a branch-only rule
  such as `main` would block every run; the workflow separately proves the tag is
  reachable from `main` and matches the workspace version.

The environment check in `publish.yml` reads the environment through the read-only
`GITHUB_TOKEN` and fails unless both conditions hold. Configure or verify them with:

```bash
gh api repos/starknet-innovation/krusty-kms/environments/crates-io \
  --jq '{reviewers: [.protection_rules[] | select(.type=="required_reviewers") | .reviewers[].reviewer.login], policy: .deployment_branch_policy}'
gh api repos/starknet-innovation/krusty-kms/environments/crates-io/deployment-branch-policies \
  --jq '.branch_policies[] | {name, type}'
```

### Release-tag rulesets

Release tags are immutable by convention; tag rulesets make that a server-side
guarantee. Two rulesets exist (created 2026-09-02, ids 22105094 and 22105099):

1. **Release tags: creation** — only bypass actors may push a `v*` tag.
2. **Release tags: immutability** — nobody may update, delete, or force-move an
   existing `v*` tag except bypass actors.

Both use the repository **Admin** role as the sole bypass actor (the rulesets API
accepts `Team`, `RepositoryRole`, `OrganizationAdmin`, and `Integration` actors, not
individual users, and this repository has no team with access). Keeping the
two rulesets separate matters when the bypass sets diverge: if a maintainers
team is later given the creation bypass, do **not** add it to the immutability
ruleset, otherwise a compromised maintainer write token could repoint a published
tag. An Admin bypass on the immutability ruleset does not widen what admins can
already do (they can edit or disable the ruleset in settings, which is audited),
but it does mean a compromised **admin** token can move a tag; drop the bypass
actor from that ruleset if the release flow never needs it.

To recreate them (administrator, `repo` scope):

```bash
gh api -X POST repos/starknet-innovation/krusty-kms/rulesets \
  --input - <<EOF
{
  "name": "Release tags: creation",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "creation" } ]
}
EOF
gh api -X POST repos/starknet-innovation/krusty-kms/rulesets \
  --input - <<EOF
{
  "name": "Release tags: immutability",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [
    { "type": "update" },
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ]
}
EOF
```

`actor_id` 5 is the Admin repository role; to hand tag creation to a team instead,
replace that entry in the **creation** ruleset with
`{ "actor_id": <team id>, "actor_type": "Team", "bypass_mode": "always" }`
(`gh api orgs/starknet-innovation/teams/<slug> --jq .id`). Review the live state with
`gh api repos/starknet-innovation/krusty-kms/rulesets` and keep both rulesets
`active`; never switch one to `evaluate` to get a release through — fix the tag flow
instead.

## Prepare a release

1. Begin from current `main`, whose workspace version must match the latest published
   `krusty-kms` version, and make a focused release branch. Do not create a second
   version bump while a previous release version is pending publication.
2. Change the root `[workspace.package].version` in `Cargo.toml`. Workspace crates
   inherit this version; do not assign a one-off version to an individual published crate.
   For a pre-1.0 minor release, update any internal path dependency requirements whose
   caret range does not include the new workspace version.
3. Create the release entry in `CHANGELOG.md` using the workspace version and release
   date. Include at least one concise bullet describing the user-visible change:

   ```md
   ## [0.5.5] - 2026-08-10

   ### Changed

   - Describe the release.
   ```

   Keep `## [Unreleased]` at the top for changes that are not yet released.

4. Refresh `Cargo.lock` and verify the version is consistent:

   ```bash
   cargo check --workspace --all-targets
   cargo metadata --no-deps --format-version 1 \
     | jq -r '.packages[] | select(.name == "krusty-kms") | .version'
   ```

5. Run the release preflight locally. It matches the workflow's publishable package set:

   ```bash
   cargo package --locked --workspace \
     --exclude krusty-kms-oracle \
     --exclude krusty-kms-wasm \
     --exclude krusty-kms-cabi \
     --exclude mental-poker \
     --exclude mental-poker-wasm \
     --exclude qb-game
   ```

6. Run the normal checks appropriate to the change, open the release PR, and merge it
   into `main`. Do not publish from the branch or before the PR is merged.

## Publish the merged release

On the merged `main` commit, derive the tag from the root package version and push it:

```bash
git switch main
git pull --ff-only origin main
version="$(cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "krusty-kms") | .version')"
git tag -a "v${version}" -m "Release ${version}"
git push origin "v${version}"
```

Do not pre-create the tag on a release branch. Do not use `--force`.

Open the resulting GitHub Actions run and wait for the designated reviewer to approve
the `crates-io` deployment. After approval the workflow verifies the tag and packages,
authenticates with OIDC, publishes the crates in dependency order, waits for each to
appear on crates.io, and revokes the token.

## Verify and recover

The release is complete only when the `Publish to crates.io` workflow is successful and
the log reports each crate as visible on crates.io.

```bash
gh run list --workflow publish.yml --limit 5
gh run view <run-id> --log-failed
```

If a run is interrupted or fails after some crates were published, rerun the **same**
workflow run. `.github/scripts/publish-crate.sh` checks the exact crate version first,
so already-published crates are skipped and the remaining crates continue in dependency
order.

If the failure requires changing source, package metadata, or the workflow, do not reuse
the existing tag. Make the fix on a new branch, increment the patch version, merge it,
and create a new tag. Crates.io releases and Git tags are immutable.

If a tag is cancelled before publishing, keep the tag intact. The next release PR must
reconcile the workspace version with the latest published crate version; the CI release
version check permits only that downward reconciliation, never another upward version
bump from an unpublished base.
