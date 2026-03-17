#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MANIFEST_PATH="$SCRIPT_DIR/Scarb.toml"
CLASS_MANIFEST="$SCRIPT_DIR/class-hashes.json"
PACKAGE_NAME="oz_account"
CONTRACT_NAME="AccountUpgradeable"

usage() {
  cat <<'EOF'
Usage: ensure_declared.sh [--network sepolia|mainnet] [--rpc-url URL] [--version VERSION] [--declare]

Checks whether the manifest-backed OpenZeppelin account class hash is declared
on the target network. If `--declare` is passed, submits `sncast declare` when
the class is missing.

Requirements for declaration:
- `sncast` must already be configured with an account/profile able to declare.
- The current shell environment must provide any required auth for `sncast`.
EOF
}

network="sepolia"
rpc_url=""
version=""
declare_if_missing="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --network)
      network="$2"
      shift 2
      ;;
    --rpc-url)
      rpc_url="$2"
      shift 2
      ;;
    --version)
      version="$2"
      shift 2
      ;;
    --declare)
      declare_if_missing="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$version" ]]; then
  version=$(jq -r '.latest_version' "$CLASS_MANIFEST")
fi

case "$network" in
  sepolia)
    chain_id="SN_SEPOLIA"
    default_rpc_url="https://api.cartridge.gg/x/starknet/sepolia"
    ;;
  mainnet)
    chain_id="SN_MAIN"
    default_rpc_url="https://api.cartridge.gg/x/starknet/mainnet"
    ;;
  *)
    echo "Unsupported network: $network" >&2
    exit 1
    ;;
esac

if [[ -z "$rpc_url" ]]; then
  rpc_url="$default_rpc_url"
fi

class_hash=$(jq -r --arg version "$version" --arg chain_id "$chain_id" '
  .versions[$version].networks[$chain_id].declared_class_hash // empty
' "$CLASS_MANIFEST")

if [[ -z "$class_hash" ]]; then
  echo "No class hash configured for version=$version chain_id=$chain_id" >&2
  exit 1
fi

echo "Building $PACKAGE_NAME ($version)..."
scarb --manifest-path "$MANIFEST_PATH" build

rpc_payload=$(jq -cn --arg class_hash "$class_hash" '{
  jsonrpc: "2.0",
  id: 1,
  method: "starknet_getClass",
  params: ["latest", $class_hash]
}')

rpc_response=$(curl -s "$rpc_url" -H 'content-type: application/json' -d "$rpc_payload")

if jq -e '.result' >/dev/null <<<"$rpc_response"; then
  echo "Class hash already declared on $network: $class_hash"
  exit 0
fi

error_message=$(jq -r '.error.message // "unknown rpc error"' <<<"$rpc_response")
echo "Class hash not declared on $network: $class_hash"
echo "RPC response: $error_message"

if [[ "$declare_if_missing" != "true" ]]; then
  exit 2
fi

echo "Declaring $CONTRACT_NAME via sncast..."
sncast declare \
  --contract-name "$CONTRACT_NAME" \
  --package "$PACKAGE_NAME" \
  --url "$rpc_url"
