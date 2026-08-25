#!/usr/bin/env bash
set -euo pipefail

package_tarball="${1:?usage: publish-npm.sh <package-tarball>}"
expected_package_name="@starknetfoundation/krusty-kms-wasm"

if [[ ! -f "$package_tarball" || "$package_tarball" != *.tgz ]]; then
  echo "::error::missing npm package tarball: $package_tarball"
  exit 1
fi

package_json="$(mktemp)"
registry_output="$(mktemp)"
trap 'rm -f "$package_json" "$registry_output"' EXIT

if ! tar --extract --to-stdout --file "$package_tarball" package/package.json >"$package_json"; then
  echo "::error::npm tarball does not contain package/package.json"
  exit 1
fi

package_metadata_output=""
if ! package_metadata_output="$(node - "$package_json" <<'NODE'
const fs = require("node:fs");
const packageJson = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (Object.hasOwn(packageJson, "scripts")) {
  throw new Error("npm package must not contain a scripts key");
}
if (typeof packageJson.name !== "string" || typeof packageJson.version !== "string") {
  throw new Error("npm package must contain string name and version fields");
}
process.stdout.write(`${packageJson.name}\n${packageJson.version}\n`);
NODE
)"; then
  echo "::error::could not validate npm package metadata"
  exit 1
fi
readarray -t package_metadata <<<"$package_metadata_output"

if ((${#package_metadata[@]} != 2)); then
  echo "::error::could not read npm package name and version"
  exit 1
fi

package_name="${package_metadata[0]}"
package_version="${package_metadata[1]}"
if [[ "$package_name" != "$expected_package_name" ]]; then
  echo "::error::unexpected npm package name: $package_name"
  exit 1
fi

package_spec="$package_name@$package_version"

# Inspect the exact downloaded tarball without allowing package lifecycle hooks.
npm pack --dry-run --ignore-scripts "$package_tarball"

if npm view "$package_spec" version --registry=https://registry.npmjs.org >"$registry_output" 2>&1; then
  echo "$package_spec is already published; skipping"
  exit 0
fi

if ! grep -Eqi '(E404|404 Not Found)' "$registry_output"; then
  cat "$registry_output"
  echo "::error::could not determine whether $package_spec is already published"
  exit 1
fi

echo "Publishing $package_spec"
# --provenance: attach a signed build attestation (the workflow already grants
# id-token: write) so consumers can verify the package was built by this repo's
# CI rather than an arbitrary publisher token.
npm publish "$package_tarball" \
  --ignore-scripts \
  --access public \
  --provenance \
  --registry=https://registry.npmjs.org
