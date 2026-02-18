#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_HEADER="$ROOT_DIR/zig/include/kms.h"

if [[ ! -f "$SRC_HEADER" ]]; then
  echo "missing source header: $SRC_HEADER" >&2
  exit 1
fi

DEST_HEADERS=(
  "$ROOT_DIR/packages/kms-c/include/kms.h"
  "$ROOT_DIR/packages/kms-go/internal/ffi/kms.h"
  "$ROOT_DIR/packages/kms-swift/Sources/CKms/include/kms.h"
  "$ROOT_DIR/packages/kms-jvm/src/main/c/kms.h"
)

for dest in "${DEST_HEADERS[@]}"; do
  mkdir -p "$(dirname "$dest")"
  cp "$SRC_HEADER" "$dest"
  echo "synced: $dest"
done
