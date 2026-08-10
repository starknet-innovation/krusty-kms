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

## Prepare a release

1. Begin from current `main` and make a focused release branch.
2. Change only the root `[workspace.package].version` in `Cargo.toml`. Workspace crates
   inherit this version; do not assign a one-off version to an individual published crate.
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
