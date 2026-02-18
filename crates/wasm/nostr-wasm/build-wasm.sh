#!/bin/bash
# Build nostr-wasm (standard single-threaded version)
#
# Requirements:
# - wasm-pack: cargo install wasm-pack
#
# Usage:
#   ./build-wasm.sh          # Release build (default)
#   ./build-wasm.sh --dev    # Dev build

set -e

# Parse arguments
BUILD_MODE="--release"
if [[ "$1" == "--dev" ]]; then
    BUILD_MODE="--dev"
fi

# Directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building nostr-wasm (single-threaded) ==="
echo ""

# Check for wasm-pack
if ! command -v wasm-pack &>/dev/null; then
    echo "Error: wasm-pack not found."
    echo "Install with: cargo install wasm-pack"
    exit 1
fi

echo "Build mode: $BUILD_MODE"
echo ""

# Build using wasm-pack
wasm-pack build \
    $BUILD_MODE \
    --target web \
    --out-dir pkg

echo ""
echo "=== Build complete ==="
echo "Output in: $SCRIPT_DIR/pkg/"
