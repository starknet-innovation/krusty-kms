#!/usr/bin/env bash
# Install the wasm-bindgen CLI from crates.io at exactly the `wasm-bindgen`
# version in Cargo.lock.
#
# wasm-pack needs a wasm-bindgen CLI of that version to generate the JS glue
# and the final .wasm. When none is on PATH it downloads a prebuilt tarball
# from GitHub releases with no checksum or signature check. Installing the
# CLI here, then running wasm-pack with `--mode no-install`, keeps the whole
# WASM toolchain built from content-addressed crates.io sources and makes
# any download attempt a hard failure.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

version="$(awk '
  /^name = "wasm-bindgen"$/ { want = 1; next }
  want && /^version = / { gsub(/^version = "|"$/, ""); print; exit }
' Cargo.lock)"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::could not read the wasm-bindgen version from Cargo.lock (got '${version}')" >&2
  exit 1
fi

cargo install wasm-bindgen-cli --version "$version" --locked

installed="$(wasm-bindgen --version)"
if [[ "$installed" != "wasm-bindgen $version" ]]; then
  echo "::error::wasm-bindgen on PATH reports '${installed}', expected 'wasm-bindgen ${version}'" >&2
  exit 1
fi
echo "wasm-bindgen-cli ${version} is installed from crates.io and matches Cargo.lock"
