#!/usr/bin/env bash
set -euo pipefail

crate="$1"
version="$(cargo metadata --no-deps --format-version 1 \
  | jq -r ".packages[] | select(.name==\"${crate}\") | .version")"

is_published() {
  cargo search "${crate}" --limit 1 | grep -q "^${crate} = \"${version}\""
}

if is_published; then
  echo "${crate}@${version} already published, skipping"
  exit 0
fi

cargo publish -p "${crate}"

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
