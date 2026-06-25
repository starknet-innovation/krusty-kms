#!/usr/bin/env bash
set -euo pipefail

crate="$1"
user_agent="krusty-kms-ci (https://github.com/starknet-innovation/krusty-kms)"
version="$(cargo metadata --no-deps --format-version 1 \
  | jq -r ".packages[] | select(.name==\"${crate}\") | .version")"

if [[ -z "${version}" || "${version}" == "null" ]]; then
  echo "::error::crate ${crate} was not found in cargo metadata"
  exit 1
fi

is_published() {
  curl -fsS -A "${user_agent}" \
    "https://crates.io/api/v1/crates/${crate}/${version}" \
    >/dev/null
}

if is_published; then
  echo "${crate}@${version} already published, skipping"
  exit 0
fi

publish_log="$(mktemp)"
if ! cargo publish -p "${crate}" 2>&1 | tee "${publish_log}"; then
  if grep -qi "already exists on crates.io index" "${publish_log}"; then
    echo "${crate}@${version} already published, skipping"
    exit 0
  fi

  exit 1
fi

for attempt in {1..20}; do
  if is_published; then
    echo "${crate}@${version} is visible on crates.io"
    exit 0
  fi

  echo "waiting for ${crate}@${version} to appear on crates.io (${attempt}/20)"
  sleep 15
done

echo "::error::${crate}@${version} was published but did not become visible in time"
exit 1
