#!/usr/bin/env bash
set -euo pipefail

package_dir="${1:?usage: publish-npm.sh <package-directory>}"
package_json="$package_dir/package.json"

if [[ ! -f "$package_json" ]]; then
  echo "::error::missing package metadata: $package_json"
  exit 1
fi

package_name="$(node -p 'JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).name' "$package_json")"
package_version="$(node -p 'JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).version' "$package_json")"
package_spec="$package_name@$package_version"
registry_output="$(mktemp)"

if npm view "$package_spec" version --registry=https://registry.npmjs.org >"$registry_output" 2>&1; then
  echo "$package_spec is already published; skipping"
  rm -f "$registry_output"
  exit 0
fi

if ! grep -Eqi '(E404|404 Not Found)' "$registry_output"; then
  cat "$registry_output"
  rm -f "$registry_output"
  echo "::error::could not determine whether $package_spec is already published"
  exit 1
fi

rm -f "$registry_output"
echo "Publishing $package_spec"
cd "$package_dir"
# --provenance: attach a signed build attestation (the workflow already grants
# id-token: write) so consumers can verify the package was built by this repo's
# CI rather than an arbitrary publisher token.
npm publish --access public --provenance --registry=https://registry.npmjs.org
