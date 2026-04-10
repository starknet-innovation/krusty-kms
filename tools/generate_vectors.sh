#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_MANIFEST="$ROOT_DIR/tools/rust-oracle/Cargo.toml"
OUT_DIR="$ROOT_DIR/fixtures/vectors"

MNEMONIC="habit hope tip crystal because grunt nation idea electric witness alert like"

mkdir -p "$OUT_DIR"

echo "Generating coin_derivation_vectors.json"
cat > "$OUT_DIR/coin_derivation_vectors.json" <<JSON
{
  "mnemonic": "$MNEMONIC",
  "passphrase": "",
  "vectors": [
    {
      "name": "starknet-coin-9004-index-0-account-0",
      "coin_type": 9004,
      "index": 0,
      "account_index": 0,
      "expected_private_key": "$(cargo run --manifest-path "$ORACLE_MANIFEST" --quiet -- derive-private "$MNEMONIC" 0 0 9004)"
    },
    {
      "name": "tongo-coin-5454-index-0-account-0",
      "coin_type": 5454,
      "index": 0,
      "account_index": 0,
      "expected_private_key": "$(cargo run --manifest-path "$ORACLE_MANIFEST" --quiet -- derive-private "$MNEMONIC" 0 0 5454)"
    }
  ]
}
JSON

echo "Generating nostr_derivation_vectors.json"
NOSTR_JSON="$(cargo run --manifest-path "$ORACLE_MANIFEST" --quiet -- derive-nostr "$MNEMONIC" 0 0)"
cat > "$OUT_DIR/nostr_derivation_vectors.json" <<JSON
{
  "vectors": [
    {
      "name": "nostr-slip44-1237-index-0-account-0",
      "mnemonic": "$MNEMONIC",
      "coin_type": 1237,
      "index": 0,
      "account_index": 0,
      "expected_private_key_hex": "$(echo "$NOSTR_JSON" | jq -r '.private_key_hex')",
      "expected_public_key_xonly_hex": "$(echo "$NOSTR_JSON" | jq -r '.public_key_xonly_hex')"
    }
  ]
}
JSON

echo "Vector generation complete."
